//models/user.js

let mongoose = require('mongoose');
let bcrypt = require('bcryptjs');

let userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);

//authController.js

let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let User = require('../models/user');
let dotenv = require('dotenv');

dotenv.config();

let register = async (req, res) => {
  let { username, password, role } = req.body;

  try {
    let userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    let newUser = new User({ username, password, role });
    await newUser.save();

    let token = jwt.sign({ id: newUser._id, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

let login = async (req, res) => {
  let { username, password } = req.body;

  try {
    let user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'User not found' });

    let isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    let token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = { register, login };

//authMiddleware.js

let jwt = require('jsonwebtoken');
let dotenv = require('dotenv');

dotenv.config();

let authMiddleware = (req, res, next) => {
  let token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    let decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

let adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
  next();
};

module.exports = { authMiddleware, adminMiddleware };


//models/task.js

let mongoose = require('mongoose');

let taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  category: { type: String, enum: ['Development', 'Design', 'Marketing', 'Research', 'Other'], required: true },
  priority: { type: String, enum: ['Low', 'Medium', 'High'], required: true },
  dueDate: { type: Date, required: true },
  status: { type: String, enum: ['Pending', 'In Progress', 'Completed'], default: 'Pending' },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

module.exports = mongoose.model('Task', taskSchema);


//taskController.js

let Task = require('../models/task');
let redis = require('redis');
let client = redis.createClient();

let createTask = async (req, res) => {
  let { title, description, category, priority, dueDate, status } = req.body;

  try {
    let task = new Task({ title, description, category, priority, dueDate, status, user: req.user.id });
    await task.save();
    res.status(201).json(task);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// More CRUD methods for read, update, delete

module.exports = { createTask };


//models/category.js

let mongoose = require('mongoose');

let categorySchema = new mongoose.Schema({
  name: { type: String, enum: ['Development', 'Design', 'Marketing', 'Research', 'Other'], required: true },
  description: { type: String },
});

module.exports = mongoose.model('Category', categorySchema);


//categoryController.js

let Category = require('../models/category');

let createCategory = async (req, res) => {
  const { name, description } = req.body;

  try {
    let category = new Category({ name, description });
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// More CRUD methods for update, delete, and view categories


//Redis Caching

let getCachedTasks = async (userId) => {
    return new Promise((resolve, reject) => {
      client.get(`tasks:${userId}`, (err, data) => {
        if (err) reject(err);
        if (data) return resolve(JSON.parse(data));
        resolve(null);
      });
    });
  };
  
  let setCachedTasks = async (userId, tasks) => {
    client.setex(`tasks:${userId}`, 3600, JSON.stringify(tasks)); // Cache for 1 hour
  };

  
  //utils/cronJob.js

  let cron = require('node-cron');
let Task = require('../models/task');

cron.schedule('* * * * *', async () => {
  let highPriorityTasks = await Task.countDocuments({ priority: 'High' });
  let pendingTasks = await Task.countDocuments({ status: 'Pending' });

  console.log(`High Priority Tasks: ${highPriorityTasks}`);
  console.log(`Pending Tasks: ${pendingTasks}`);
});
