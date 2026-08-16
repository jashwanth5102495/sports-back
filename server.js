// Trigger Railway Redeploy
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
app.set('trust proxy', 1); // Trust first proxy (required for Railway and express-rate-limit)

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

const Message = sequelize.define('Message', {
  firstName: DataTypes.STRING,
  lastName: DataTypes.STRING,
  email: DataTypes.STRING,
  phone: DataTypes.STRING,
  message: DataTypes.TEXT,
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

const SiteContent = sequelize.define('SiteContent', {
  sectionKey: { type: DataTypes.STRING, unique: true, allowNull: false },
  content: { type: DataTypes.TEXT, allowNull: false },
});

const Video = sequelize.define('Video', {
  title: { type: DataTypes.STRING, allowNull: false },
  youtubeUrl: { type: DataTypes.STRING, allowNull: false },
  duration: { type: DataTypes.STRING, defaultValue: '03:00' },
  featured: { type: DataTypes.BOOLEAN, defaultValue: false }
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

      const defaultStatistics = JSON.stringify([
        { label: 'CAREER POINTS', value: 368 },
        { label: 'CAREER ASSISTS', value: 197 },
        { label: 'CAREER GOALS', value: 171 },
        { label: 'NCAA NATIONAL CHAMPION', value: 1 },
        { label: 'ALL-AMERICAN', value: 2 },
        { label: 'BIG TEN CHAMPIONSHIPS', value: 3 },
        { label: 'ESPN SPORTSCENTER TOP 10', value: 4 },
      ]);

      const defaultHeroStats = JSON.stringify([
        { label: 'POINTS', value: 368 },
        { label: 'GOALS', value: 171 },
        { label: 'ASSISTS', value: 197 },
        { label: 'ALL-AMER', value: 2 },
        { label: "NAT'L CHAMP", value: 1 },
        { label: 'ALL-B1G', value: 3 },
      ]);

      const defaultSiteContent = [
        { sectionKey: 'about_bio', content: "From a backyard rebounder in Spencerport to a national championship at Northwestern and the professional game, Erin Coykendall's career has been built on creativity, preparation and seeing the field differently. Her Northwestern career evolved from elite feeder to complete attacking threat — without losing the unselfish playmaking that made her game unique. Off the field, she is a huge dog lover and proud owner of two dachshunds — Tractor and Lunch Lady." },
        { sectionKey: 'about_playingStyle', content: "A creative attacker who sees the field differently. Known for her elite lacrosse IQ, exceptional feeding ability, and confidence under pressure." },
        { sectionKey: 'about_highSchool', content: "Ranked No. 22 by Inside Lacrosse. 3x team captain, 4x First-Team All-County, 2018 First Team All-State, and 2018 Max Preps National Athlete of the Year. Wendy's High School Heisman State Winner & National Finalist. 2018 Divisional/Section/Regional Champions and State Semifinalists." },
        { sectionKey: 'about_personal', content: "Born in Rochester, N.Y. Parents are Scott and Jennifer Coykendall. Competed for Common Goal Lacrosse. National Honor Society & National Spanish Honor Society Member, and recipient of the Academic Excellence Award." },
        { sectionKey: 'journey_description', content: "From the time she picked up a lacrosse stick at just 3 years old, Erin's passion for the game was clear. She progressed through youth, club, and high school lacrosse, ultimately becoming one of the most accomplished players in Northwestern University's history. Erin continued pursuing her dream at the professional level, competing in both the AU Pro Lacrosse League and the Women's Lacrosse League, inspiring the next generation of players through her dedication, talent, and love for the game." },
        { sectionKey: 'achievements_description', content: "A testament to excellence and consistent performance at the highest level of the sport." },
        { sectionKey: 'featured_year', content: '2026' },
        { sectionKey: 'featured_title', content: 'Championship Series Winner' },
        { sectionKey: 'featured_description', content: 'Won the prestigious 2026 Championship series.' },
        { sectionKey: 'statistics', content: defaultStatistics },
        { sectionKey: 'hero_stats', content: defaultHeroStats },
        { sectionKey: 'contact_description', content: 'For Skills Sessions, Private Groups, Team Training, Camps/Clinics, and media requests, please use the form or reach out directly.' },
        { sectionKey: 'contact_email', content: 'erincoykendalllax@gmail.com' },
        { sectionKey: 'contact_instagram', content: 'https://www.instagram.com/erincoykendall/?hl=en' },
        { sectionKey: 'events_empty_message', content: 'Updates will be posted here. Check back soon for upcoming events and appearances.' },
      ];

      // Seed default site content if not exists, and ensure new keys exist for existing installs
      const contentCount = await SiteContent.count();
      if (contentCount === 0) {
        await SiteContent.bulkCreate(defaultSiteContent);
        console.log('Default site content seeded.');
      } else {
        for (const item of defaultSiteContent) {
          const existing = await SiteContent.findOne({ where: { sectionKey: item.sectionKey } });
          if (!existing) {
            await SiteContent.create(item);
          }
        }
      }

      // Seed default videos if empty
      const videoCount = await Video.count();
      if (videoCount === 0) {
        await Video.bulkCreate([
          {
            title: "The Journey to the Final",
            youtubeUrl: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            duration: "12:45",
            featured: true
          },
          {
            title: "Top 10 Assists of the Season",
            youtubeUrl: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            duration: "04:30",
            featured: false
          },
          {
            title: "Training Ground Masterclass",
            youtubeUrl: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            duration: "08:15",
            featured: false
          }
        ]);
        console.log('Default videos seeded.');
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

app.get('/api/site-content', async (req, res) => {
  try {
    const content = await SiteContent.findAll();
    res.status(200).json(content);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/videos', async (req, res) => {
  try {
    const videos = await Video.findAll({ order: [['featured', 'DESC'], ['createdAt', 'DESC']] });
    res.status(200).json(videos);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/site-content', authenticateToken, async (req, res) => {
  try {
    const items = req.body; // Array of { sectionKey, content }
    if (!Array.isArray(items)) return res.status(400).json({ error: 'Expected an array of { sectionKey, content }' });
    
    for (const item of items) {
      await SiteContent.upsert({ sectionKey: item.sectionKey, content: item.content });
    }
    
    const updated = await SiteContent.findAll();
    res.status(200).json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/messages', async (req, res) => {
  try {
    const newMessage = await Message.create(req.body);
    res.status(201).json(newMessage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected Content Routes
app.post('/api/videos', authenticateToken, async (req, res) => {
  try {
    const { title, youtubeUrl, duration, featured } = req.body;
    
    // If setting as featured, unfeature others
    if (featured) {
      await Video.update({ featured: false }, { where: { featured: true } });
    }
    
    const newVideo = await Video.create({ title, youtubeUrl, duration, featured });
    res.status(201).json(newVideo);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/videos/:id', authenticateToken, async (req, res) => {
  try {
    const video = await Video.findByPk(req.params.id);
    if (!video) return res.status(404).json({ error: 'Video not found' });
    await video.destroy();
    res.status(200).json({ success: true, message: 'Video deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.post('/api/updates', authenticateToken, async (req, res) => {
  try {
    const payload = { ...req.body };
    if (payload.image) {
      payload.image = await uploadBase64ToS3(payload.image, 'news');
    }
    const newUpdate = await Update.create(payload);
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

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    const event = await Event.findByPk(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });

    // Try to delete from MinIO if it's an S3 URL
    if (event.image && event.image.includes(MINIO_BUCKET)) {
      try {
        const parts = event.image.split('/');
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

    await event.destroy();
    res.status(200).json({ success: true, message: 'Event deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.findAll({ order: [['createdAt', 'DESC']] });
    res.status(200).json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const message = await Message.findByPk(req.params.id);
    if (!message) return res.status(404).json({ error: 'Message not found' });
    await message.destroy();
    res.status(200).json({ success: true, message: 'Message deleted' });
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


