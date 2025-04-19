const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Configure CORS
const corsOptions = {
    origin: ['https://altamimi004.github.io', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.use(cors(corsOptions));

// Handle OPTIONS requests
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(express.static('public'));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/portfolio', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Models
const User = mongoose.model('User', {
    username: String,
    password: String
});

const Content = mongoose.model('Content', {
    section: String,
    content: Object,
    lastUpdated: { type: Date, default: Date.now }
});

// Image upload setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ token });
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    try {
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(400).json({ message: 'Error creating user' });
    }
});

app.post('/api/upload', authenticateToken, upload.single('image'), (req, res) => {
    res.json({ url: `/uploads/${req.file.filename}` });
});

app.get('/api/content/:section', async (req, res) => {
    const content = await Content.findOne({ section: req.params.section });
    res.json(content || {});
});

app.post('/api/content/:section', authenticateToken, async (req, res) => {
    const { section } = req.params;
    const { content } = req.body;

    try {
        await Content.findOneAndUpdate(
            { section },
            { content, lastUpdated: Date.now() },
            { upsert: true }
        );
        res.json({ message: 'Content updated successfully' });
    } catch (error) {
        res.status(400).json({ message: 'Error updating content' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 