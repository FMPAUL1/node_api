const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const dotenv = require('dotenv').config();
const app = express();
const PORT = 3000;

// Connect to MongoDB Atlas
mongoose.connect(`process.env.MONGODB_URI`, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB Atlas, ');
});

app.use(bodyParser.json());

const User = require('./models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Registration route
app.post(
  '/register',
  [
    check('username').isLength({ min: 5 }),
    check('password').isLength({ min: 5 }),
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      // Check if username already exists
      const existingUser = await User.findOne({ username: req.body.username });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      // Hash the password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

      // Create a new user
      const newUser = new User({
        username: req.body.username,
        password: hashedPassword,
      });

      await newUser.save();

      res.json({ message: 'User registered successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  }
);

app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const passwordMatch = await bcrypt.compare(req.body.password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'This is a protected route', userId: req.userId });
});

app.listen(PORT, () => {
  console.log(`The server is running on port ${PORT}`);
});
