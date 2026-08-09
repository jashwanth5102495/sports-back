const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-change-in-prod';

// Security Middleware
app.use(helmet()); // Secure HTTP headers
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate Limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 login requests per windowMs
  message: 'Too many login attempts, please try again later.'
});

app.use(globalLimiter);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access Denied: No token provided' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Access Denied: Invalid token' });
    req.user = user;
    next();
  });
};

// Database Connection
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.warn('WARNING: MONGODB_URI is not defined. Database will not connect.');
} else {
  mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));
}

// Models
const updateSchema = new mongoose.Schema({
  title: String,
  date: String,
  category: String,
  excerpt: String,
  image: String,
  createdAt: { type: Date, default: Date.now }
});
const Update = mongoose.models.Update || mongoose.model('Update', updateSchema);

const imageSchema = new mongoose.Schema({
  title: String,
  base64Data: String,
  createdAt: { type: Date, default: Date.now }
});
const CustomImage = mongoose.models.CustomImage || mongoose.model('CustomImage', imageSchema);

const adminUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const AdminUser = mongoose.models.AdminUser || mongoose.model('AdminUser', adminUserSchema);

const visitorSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now }
});
const Visitor = mongoose.models.Visitor || mongoose.model('Visitor', visitorSchema);

// Initialize default admin
async function initializeAdmin() {
  try {
    const adminExists = await AdminUser.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await AdminUser.create({ username: 'admin', password: hashedPassword });
      console.log('Default admin user created.');
    }
  } catch (err) {
    console.error('Error initializing admin user:', err);
  }
}
if (MONGODB_URI) {
  mongoose.connection.once('open', () => {
    initializeAdmin();
  });
}

// Routes
// Public Routes
app.get('/api/updates', async (req, res) => {
  try {
    const updates = await Update.find({}).sort({ createdAt: -1 });
    res.status(200).json(updates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/images', async (req, res) => {
  try {
    const images = await CustomImage.find({}).sort({ createdAt: -1 });
    res.status(200).json(images);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/track', async (req, res) => {
  try {
    // Simply record a hit with a timestamp.
    await Visitor.create({});
    res.status(200).send('OK');
  } catch (error) {
    res.status(500).send('Error');
  }
});

// Protected Content Routes
app.post('/api/updates', authenticateToken, async (req, res) => {
  try {
    const newUpdate = await Update.create(req.body);
    res.status(201).json(newUpdate);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/images', authenticateToken, async (req, res) => {
  try {
    const newImage = await CustomImage.create(req.body);
    res.status(201).json(newImage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const query = {};
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) {
        let end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        query.timestamp.$lte = end;
      }
    }
    const visitors = await Visitor.find(query).sort({ timestamp: -1 });
    res.status(200).json({ count: visitors.length, data: visitors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Auth Routes
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await AdminUser.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
    res.status(200).json({ success: true, token, message: 'Logged in' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  try {
    const user = await AdminUser.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect current password' });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send('Sports Backend API is running securely.');
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
