const express = require('express');
const { Sequelize, DataTypes, Op } = require('sequelize');
const { S3Client, PutObjectCommand, CreateBucketCommand, PutBucketPolicyCommand, HeadBucketCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
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

// MinIO / S3 Configuration
const s3 = new S3Client({
  endpoint: process.env.MINIO_ENDPOINT || 'https://minio-production-b44d.up.railway.app', 
  region: process.env.MINIO_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.MINIO_ACCESS_KEY || process.env.MINIO_ROOT_USER,
    secretAccessKey: process.env.MINIO_SECRET_KEY || process.env.MINIO_ROOT_PASSWORD,
  },
  forcePathStyle: true, // Required for MinIO
});

const MINIO_BUCKET = process.env.MINIO_BUCKET || 'sports-images';
const MINIO_PUBLIC_URL = process.env.MINIO_PUBLIC_URL || process.env.MINIO_ENDPOINT || 'https://minio-production-b44d.up.railway.app';

// Automatically make the bucket public on startup so the frontend can read the images!
async function ensureBucketExistsAndPublic() {
  if (!process.env.MINIO_ENDPOINT) return; // Skip if MinIO not configured
  
  try {
    // Check if bucket exists, if not create it
    try {
      await s3.send(new HeadBucketCommand({ Bucket: MINIO_BUCKET }));
    } catch (err) {
      if (err.name === 'NotFound') {
        await s3.send(new CreateBucketCommand({ Bucket: MINIO_BUCKET }));
        console.log(`Created bucket: ${MINIO_BUCKET}`);
      }
    }

    // Set bucket policy to public read
    const policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "PublicReadGetObject",
          Effect: "Allow",
          Principal: "*",
          Action: "s3:GetObject",
          Resource: `arn:aws:s3:::${MINIO_BUCKET}/*`
        }
      ]
    };
    
    await s3.send(new PutBucketPolicyCommand({
      Bucket: MINIO_BUCKET,
      Policy: JSON.stringify(policy)
    }));
    console.log(`Bucket ${MINIO_BUCKET} is now PUBLIC.`);
  } catch (err) {
    console.error("Warning: Failed to configure bucket policy automatically:", err.message);
  }
}

async function uploadBase64ToS3(base64String, prefix = 'image') {
  // If it's not a base64 string, just return it (might already be a URL or empty)
  if (!base64String || !base64String.startsWith('data:image')) {
    return base64String;
  }

  const matches = base64String.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) {
    throw new Error('Invalid base64 string format');
  }

  const mimeType = matches[1];
  const buffer = Buffer.from(matches[2], 'base64');
  const extension = mimeType.split('/')[1];
  const fileName = `${prefix}-${Date.now()}.${extension}`;

  const command = new PutObjectCommand({
    Bucket: MINIO_BUCKET,
    Key: fileName,
    Body: buffer,
    ContentType: mimeType,
  });

  await s3.send(command);
  return `${MINIO_PUBLIC_URL}/${MINIO_BUCKET}/${fileName}`;
}

// Database Connection
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://dummy:dummy@localhost:5432/dummy';

const sequelize = new Sequelize(DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectOptions: {
    ssl: process.env.NODE_ENV === 'production' ? { require: true, rejectUnauthorized: false } : false
  }
});

if (!process.env.DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL is not defined in .env. Database will fail to connect.');
} else {
  sequelize.authenticate()
    .then(() => console.log('Connected to PostgreSQL'))
    .catch((err) => console.error('PostgreSQL connection error:', err));
}

// Models
const Update = sequelize.define('Update', {
  title: DataTypes.STRING,
  date: DataTypes.STRING,
  category: DataTypes.STRING,
  excerpt: DataTypes.TEXT,
  image: DataTypes.TEXT,
});

const Event = sequelize.define('Event', {
  title: DataTypes.STRING,
  date: DataTypes.STRING,
  description: DataTypes.TEXT,
  image: DataTypes.TEXT,
});

const CustomImage = sequelize.define('CustomImage', {
  title: DataTypes.STRING,
  base64Data: DataTypes.TEXT,
});

const AdminUser = sequelize.define('AdminUser', {
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
});

const Visitor = sequelize.define('Visitor', {
  timestamp: { type: DataTypes.DATE, defaultValue: Sequelize.NOW },
});

// Initialize default admin and server
async function startServer() {
  if (process.env.DATABASE_URL) {
    try {
      await sequelize.sync({ alter: true });
      console.log('Database connected and synced');
      
      // Seed initial admin user if not exists
      const adminCount = await AdminUser.count();
      if (adminCount === 0) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await AdminUser.create({ username: 'admin', password: hashedPassword });
        console.log('Default admin user created (admin / admin123)');
      }
    } catch (err) {
      console.error('Error syncing database:', err);
    }
  }

  // Configure MinIO Bucket automatically
  await ensureBucketExistsAndPublic();

  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

// Start the server
startServer();

// Routes
// Public Routes
app.get('/api/updates', async (req, res) => {
  try {
    const updates = await Update.findAll({ order: [['createdAt', 'DESC']] });
    res.status(200).json(updates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const events = await Event.findAll({ order: [['createdAt', 'DESC']] });
    res.status(200).json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/images', async (req, res) => {
  try {
    const images = await CustomImage.findAll({ order: [['createdAt', 'DESC']] });
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

app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const payload = { ...req.body };
    if (payload.image) {
      payload.image = await uploadBase64ToS3(payload.image, 'event');
    }
    const newEvent = await Event.create(payload);
    res.status(201).json(newEvent);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/images', authenticateToken, async (req, res) => {
  try {
    const payload = { ...req.body };
    if (payload.base64Data) {
      payload.base64Data = await uploadBase64ToS3(payload.base64Data, 'gallery');
    }
    const newImage = await CustomImage.create(payload);
    res.status(201).json(newImage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/images/:id', authenticateToken, async (req, res) => {
  try {
    const image = await CustomImage.findByPk(req.params.id);
    if (!image) return res.status(404).json({ error: 'Image not found' });

    // Try to delete from MinIO if it's an S3 URL
    if (image.base64Data && image.base64Data.includes(MINIO_BUCKET)) {
      try {
        // Extract filename from URL (e.g. https://domain.com/bucket/filename.jpg -> filename.jpg)
        const parts = image.base64Data.split('/');
        const fileName = parts[parts.length - 1];
        
        await s3.send(new DeleteObjectCommand({
          Bucket: MINIO_BUCKET,
          Key: fileName
        }));
        console.log(`Deleted ${fileName} from MinIO`);
      } catch (s3Err) {
        console.error('Failed to delete from MinIO:', s3Err);
      }
    }

    await image.destroy();
    res.status(200).json({ success: true, message: 'Image deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const where = {};
    
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp[Op.gte] = new Date(startDate);
      if (endDate) {
        let end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        where.timestamp[Op.lte] = end;
      }
    }
    
    const visitors = await Visitor.findAll({ where, order: [['timestamp', 'DESC']] });
    res.status(200).json({ count: visitors.length, data: visitors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Auth Routes
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await AdminUser.findOne({ where: { username } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
    res.status(200).json({ success: true, token, message: 'Logged in' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  try {
    const user = await AdminUser.findOne({ where: { username } });
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
  res.send('Sports Backend API is running securely with PostgreSQL.');
});


