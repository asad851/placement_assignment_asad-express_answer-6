const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Replace with your own secret key
const secretKey = 'your-secret-key';

// Temporary storage for registered users
const users = [];

// User model
class User {
  constructor(username, password) {
    this.username = username;
    this.password = password;
  }
}

// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
  
    // Check if the user already exists
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
  
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Create a new user
    const user = new User(username, hashedPassword);
    users.push(user);
  
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
  
    // Find the user
    const user = users.find(user => user.username === username);
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
  
    // Check the password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
  
    // Generate a JWT
    const token = jwt.sign({ username: user.username }, secretKey);
  
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Protected route
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully' });
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    
    req.user = user;
    next();
  });
}

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});