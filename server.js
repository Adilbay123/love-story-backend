const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const cors = require('cors');
const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB подключена'))
    .catch(err => console.error('❌ MongoDB ошибка:', err.message));

// Модели
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    totalStorageUsed: { type: Number, default: 0 },
    resetCode: { type: String },
    resetCodeExpires: { type: Date },
});
const User = mongoose.model('User', UserSchema);

const PhotoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    url: { type: String, required: true },
    publicId: { type: String, required: true },
    caption: { type: String, default: '' },
    sizeBytes: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
});
const Photo = mongoose.model('Photo', PhotoSchema);

// Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

// ========== API ==========
app.get('/', (req, res) => {
    res.json({ message: '❤️ Love Story API', status: 'running' });
});

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ email, password: hashedPassword });
        res.json({ token: generateToken(user._id), user: { email: user.email, storageUsed: 0 } });
    } catch (error) {
        res.status(400).json({ error: 'Email уже используется' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        res.json({ token: generateToken(user._id), user: { email: user.email, storageUsed: user.totalStorageUsed } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/photos', upload.single('photo'), async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const { userId } = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(userId);
        if (!user) return res.status(401).json({ error: 'Не авторизован' });

        const result = await cloudinary.uploader.upload(req.file.path, { folder: `user_${userId}` });
        const photo = await Photo.create({
            userId, url: result.secure_url, publicId: result.public_id,
            caption: req.body.caption || '', sizeBytes: result.bytes
        });
        user.totalStorageUsed += result.bytes;
        await user.save();
        res.json({ photo, storageUsed: user.totalStorageUsed, storageLimit: 2_000_000_000 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/photos', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const { userId } = jwt.verify(token, process.env.JWT_SECRET);
        const photos = await Photo.find({ userId }).sort({ createdAt: -1 });
        const user = await User.findById(userId);
        res.json({ photos, storageUsed: user.totalStorageUsed, storageLimit: 2_000_000_000 });
    } catch (error) {
        res.status(401).json({ error: 'Не авторизован' });
    }
});

app.delete('/api/photos/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const { userId } = jwt.verify(token, process.env.JWT_SECRET);
        const photo = await Photo.findOne({ _id: req.params.id, userId });
        if (!photo) return res.status(404).json({ error: 'Фото не найдено' });
        await cloudinary.uploader.destroy(photo.publicId);
        await photo.deleteOne();
        const user = await User.findById(userId);
        user.totalStorageUsed -= photo.sizeBytes;
        await user.save();
        res.json({ success: true, storageUsed: user.totalStorageUsed });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: 'Если email существует, код отправлен' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetCode = await bcrypt.hash(code, 10);
    user.resetCodeExpires = Date.now() + 3600000;
    await user.save();
    try {
        await transporter.sendMail({
            from: `"Love Story" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Восстановление пароля',
            html: `<h2>Ваш код: <b>${code}</b></h2><p>Код действителен 1 час.</p>`
        });
        res.json({ message: 'Код отправлен на email' });
    } catch (error) {
        res.json({ message: 'Ошибка отправки', code });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.resetCode || user.resetCodeExpires < Date.now()) {
        return res.status(400).json({ error: 'Код недействителен' });
    }
    if (!(await bcrypt.compare(code, user.resetCode))) {
        return res.status(400).json({ error: 'Неверный код' });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetCode = null;
    await user.save();
    res.json({ message: 'Пароль изменён' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Сервер на порту ${PORT}`));