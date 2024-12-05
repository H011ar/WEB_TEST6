const express = require('express');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Session setup
app.use(
  session({
    secret: 'your_secret_key', // Replace with a strong key
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Change secure to true if using HTTPS
  })
);

// In-memory storage for users (replace with DB in production)
const users = {};

// Routes
app.get('/', (req, res) => res.redirect('/login'));

// Register Route
app
  .route('/register')
  .get((req, res) => res.render('register', { error: '', success: '' }))
  .post(async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.render('register', { error: 'All fields are required', success: '' });
    }
    if (users[username]) {
      return res.render('register', { error: 'User already exists', success: '' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    res.render('register', { error: '', success: 'Registration successful' });
  });

// Login Route
app
  .route('/login')
  .get((req, res) => res.render('login', { error: '' }))
  .post(async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = username;
    res.redirect('/dashboard');
  });

// Dashboard Route (Protected)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('dashboard', { username: req.session.user });
});

// Logout Route
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/login');
  });
});

// 404 Route
app.use((req, res) => {
  res.status(404).render('error', { message: 'Page Not Found' });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
