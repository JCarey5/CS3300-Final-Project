const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const expressSession = require('express-session');
const bodyParser = require('body-parser');
const connectFlash = require('connect-flash');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./db'); // Import the database connection
const app = express();


//serve static files
app.use(express.static(__dirname + '/public'));



// Passport setup (use email as the username)
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  (email, password, done) => {
    // Query the database to find the user
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) return done(err);

      if (results.length === 0) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      const user = results[0];

      // Compare the entered password with the hashed password in the database
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Invalid email or password' });
        }
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

// Middleware setup
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressSession({ secret: 'secret-key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(connectFlash());
app.set('view engine', 'ejs');

// Routes

// Show the login form
app.get('/', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

// Handle login form submission
app.post('/login', passport.authenticate('local', {
  successRedirect: '/manager_dashboard',
  failureRedirect: '/',
  failureFlash: true
}));

// Register route (GET)
app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error') });
});

// Handle registration form submission (POST)
app.post('/register', (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  // Basic validation
  if (!firstName || !lastName || !email || !password) {
    req.flash('error', 'All fields are required!');
    return res.redirect('/register');
  }

  if (firstName.length > 20 || lastName.length > 20) {
    req.flash('error', 'First Name and Last Name should be less than 20 characters!');
    return res.redirect('/register');
  }

  // Email format validation (basic check)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    req.flash('error', 'Please enter a valid email address!');
    return res.redirect('/register');
  }

  // Check if email already exists in the database
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      req.flash('error', 'Database error. Please try again later.');
      return res.redirect('/register');
    }

    if (results.length > 0) {
      req.flash('error', 'Email is already taken!');
      return res.redirect('/register');
    }

    // Hash the password before saving it to the database
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        req.flash('error', 'Error hashing the password.');
        return res.redirect('/register');
      }

      // Insert the new user into the database
      const newUser = { firstName, lastName, email, password: hashedPassword };
      db.query('INSERT INTO users SET ?', newUser, (err, result) => {
        if (err) {
          req.flash('error', 'Database error. Please try again later.');
          return res.redirect('/register');
        }

        req.flash('success', 'Registration successful! You can now log in.');
        res.redirect('/');
      });
    });
  });
});

// Dashboard page (protected)
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    const userFirstName = req.user ? req.user.firstName : null;
    const userObject = {
      firstName: userFirstName
    }
    res.render('dashboard', userObject)
    //res.send(`<h1>Welcome, ${req.user.firstName} ${req.user.lastName}!</h1><p><a href="/logout">Logout</a></p>`);
  } else {
    res.redirect('/');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    res.redirect('/');
  });
});



app.get('/manager_dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    const userFirstName = req.user ? req.user.firstName : null;
    const userObject = {
      firstName: userFirstName
    }
    res.render('ManagerDashBoard', userObject)
    
  } else {
    res.redirect('/');
  }
})


app.get('/schedule_employee', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('ScheduleEmployee')
    
  } else {
    res.redirect('/');
  }
})


app.get('/view_requests', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('ViewEmployeeRequests')
    
  } else {
    res.redirect('/');
  }
})


app.get('/add_employee', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('addEmployee')
    
  } else {
    res.redirect('/');
  }
})

app.get('/view_employee', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('ViewEmployeeContacts')
    
  } else {
    res.redirect('/');
  }
})



const port = 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
