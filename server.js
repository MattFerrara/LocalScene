// server.js
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import fetch from 'node-fetch'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('Mongo error:', err))

// User Schema and Model 
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationTokenExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare password
userSchema.methods.comparePassword = function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Concert Schema and model
const concertSchema = new mongoose.Schema({
  band: String,
  address: String,
  town: String,
  state: String,
  venue: String,
  genres: [String],
  date: String,
  time: String,
  timeZone: String,
  utcTimestamp: String,
  price: Number,
  others: String,
  age: String,
  lat: Number,
  lon: Number,
  deleteAt: { type: Date, index: { expires: 0 } },
  createdAt: { type: Date, default: Date.now }
})

// Add the compound unique index to prevent duplicate shows by date, time, and address
concertSchema.index({ date: 1, time: 1, address: 1 }, { unique: true });

const Concert = mongoose.model('Concert', concertSchema)

// Nodemailer Transporter 
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_SERVICE_HOST,
  port: process.env.EMAIL_SERVICE_PORT,
  secure: false, // For port 587 (STARTTLS)
  auth: {
    user: process.env.EMAIL_AUTH_USER,
    pass: process.env.EMAIL_AUTH_PASS,
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Helper: check if show is duplicate (Still useful for band overlap, but unique index handles exact duplicates)
const isDuplicate = async (data) => {
  const shows = await Concert.find({
    date: data.date,
    time: data.time,
    address: `${data.address}, ${data.town}, ${data.state}`
  })

  const newBands = new Set(
    [data.band, ...data.others.split(',').map(b => b.trim())].map(b => b.toLowerCase())
  )

  for (let show of shows) {
    const existingBands = new Set(
      [show.band, ...show.others.split(',').map(b => b.trim())].map(b => b.toLowerCase())
    )
    for (let band of newBands) {
      if (existingBands.has(band)) return true
    }
  }

  return false
}

// Authentication Middleware
const auth = (req, res, next) => {
  const token = req.header('x-auth-token'); // Or Authorization: Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Add user ID to the request
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

// --- Routes ---

// Root route
app.get('/', (req, res) => res.send('Server and MongoDB are working'))

// POST /api/concerts (Now protected by auth middleware)
app.post('/api/concerts', auth, async (req, res) => { // <-- Added 'auth' middleware here
  try {
    const data = req.body
    const fullAddress = `${data.address}, ${data.town}, ${data.state}`

    const geoRes = await fetch(`https://geocode.maps.co/search?q=${encodeURIComponent(fullAddress)}&api_key=${process.env.GEOCODE_KEY}`)
    const geo = await geoRes.json()
    if (!geo || geo.length === 0) throw new Error('Invalid address')

    const { lat, lon } = geo[0]

    const tzRes = await fetch(`http://api.timezonedb.com/v2.1/get-time-zone?key=${process.env.TZDB_KEY}&format=json&by=position&lat=${lat}&lng=${lon}`)
    if (!tzRes.ok) throw new Error('Timezone lookup failed')
    const tzData = await tzRes.json()
    if (!tzData.zoneName) throw new Error('Could not determine time zone')

    const pseudoUTC = new Date(`${data.date}T${data.time}:00Z`).getTime()
    const utcOffsetMillis = tzData.gmtOffset * 1000
    const utcTime = new Date(pseudoUTC - utcOffsetMillis)

    if (utcTime < Date.now()) return res.status(400).json({ error: 'Date/time is in the past' })

    // Keep isDuplicate for other band overlaps, but the unique index is the primary defense against exact duplicates
    const duplicate = await isDuplicate(data); // Call without utcTimestamp
    if (duplicate) {
      return res.status(400).json({ error: 'A concert with one of these bands at the same date, time, and address already exists.' });
    }

    const concert = new Concert({
    ...data,
    address: fullAddress,
    lat,
    lon,
    timeZone: tzData.zoneName,
    utcTimestamp: utcTime.toISOString(),
    deleteAt: new Date(utcTime.getTime() + 60 * 60 * 1000)
})

    await concert.save()
    res.status(201).json(concert)
  } catch (err) {
    console.error('Error submitting concert:', err); // Log the full error for debugging

    // Handle MongoDB duplicate key error (code 11000)
    if (err.code === 11000) {
      return res.status(409).json({ error: 'This exact concert (same date, time, and address) has already been submitted.' });
    }
    res.status(500).json({ error: err.message })
  }
})

// GET /api/concerts
app.get('/api/concerts', async (req, res) => {
  try {
    const now = new Date()
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)
    const concerts = await Concert.find({ utcTimestamp: { $gte: oneHourAgo.toISOString() } })
    res.json(concerts)
  } catch (err) {
    console.error('Error fetching concerts:', err);
    res.status(500).json({ error: err.message });
  }
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    const verificationTokenExpires = Date.now() + 3600000; // 1 hour

    user = new User({
      email,
      password,
      verificationToken,
      verificationTokenExpires
    });

    await user.save();

    const verificationLink = `${req.protocol}://${req.get('host')}/api/verify-email?token=${verificationToken}`;

    await transporter.sendMail({
      to: user.email,
      from: process.env.EMAIL_AUTH_USER, // verified sender email
      subject: 'Account Verification',
      html: `<p>Please verify your account by clicking this link: <a href="${verificationLink}">${verificationLink}</a></p>`,
    });

    res.status(201).json({ message: 'Registration successful. Please check your email to verify your account.' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Email verification endpoint
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).send('Verification token is invalid or has expired.');
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    res.send('Your email has been successfully verified! You can now log in.');
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).send('Server error during email verification.');
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ error: 'Please verify your email before logging in.' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, email: user.email } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))