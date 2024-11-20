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

app.post('/register', (req, res) => {
  const { first_name, last_name, email, password, confirm_password } = req.body;

  // Server-side validation

  // Check if all fields are filled
  if (!first_name || !last_name || !email || !password || !confirm_password) {
    req.flash('error', 'Please fill out all fields.');
    return res.redirect('/register');
  }

  // Check if the passwords match
  if (password !== confirm_password) {
    req.flash('error', 'Passwords do not match.');
    return res.redirect('/register');
  }

  // Validate email format using a regular expression
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    req.flash('error', 'Please enter a valid email address.');
    return res.redirect('/register');
  }

  // Check if the email is already registered
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      req.flash('error', 'Email is already registered.');
      return res.redirect('/register');
    }

    // Hash password before storing in the database
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) throw err;

      // Insert user data into the database with organization and organizationAdmin set to NULL
      const newUser = {
        first_name,
        last_name,
        email,
        password: hashedPassword,
        organization_id: null,  // organization_id set to NULL
        organization: null,  // organization set to NULL
        organizationAdmin: null // organizationAdmin set to NULL
      };

      db.query('INSERT INTO users SET ?', newUser, (err, result) => {
        if (err) throw err;
        req.flash('success', 'Registration successful! You can log in now.');
        return res.redirect('/');
      });
    });
  });
});



// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    res.redirect('/');
  });
});



app.get('/manager_dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    const userFirstName = req.user ? req.user.first_name : null;
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
    res.render('add_employee', {messages: req.flash()})
    
  } else {
    res.redirect('/');
  }
})


//does not work correctly as of right now
app.post('/add_employee', (req, res) => {
  if (!req.isAuthenticated()) {
      return res.redirect('/login');
  }

  const userEmail = req.user.email;  // The email of the logged-in admin user
  const organizationId = req.user.organization_id || null; // Assuming the logged-in user has an organization_id

  
});





app.get('/view_employee', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('ViewEmployeeContacts')
    
  } else {
    res.redirect('/');
  }
})



app.get('/create_org', (req, res) => {
  if (req.isAuthenticated()) {
    
    res.render('create-organization', {
      messages: req.flash()})
    
  } else {
    res.redirect('/');
  }
})


// Route to handle creating the organization and adding user as admin
app.post('/create_org', (req, res) => {
  if (!req.isAuthenticated()) {
      return res.redirect('/');
  }

  const organizationName = req.body.name;
  const userEmail = req.user.email; // Email of logged-in user
  const firstName = req.user.firstName;  // First name from the user
  const lastName = req.user.lastName;    // Last name from the user
  const phoneNumber = req.user.phone_number || null;  // If phone number is missing, set to null

  // Ensure all required fields are provided
  if (!organizationName || !userEmail || !firstName || !lastName) {
      req.flash('error', 'Some fields are missing.');
      return res.redirect('/create_org');
  }

  // Check if the user is already associated with an organization
  const checkUserOrgQuery = 'SELECT * FROM organization_users WHERE email = ?';
  db.execute(checkUserOrgQuery, [userEmail], (err, result) => {
      if (err) {
          console.error('Error checking user organization:', err);
          req.flash('error', 'There was an error checking your organization status.');
          return res.redirect('/create_org');
      }

      if (result.length > 0) {
          // If the user is already associated with an organization
          req.flash('error', 'You are already associated with an organization. You cannot create another one.');
          return res.redirect('/create_org');
      }

      // Check if the organization name already exists
      const checkOrgQuery = 'SELECT * FROM organizations WHERE name = ?';
      db.execute(checkOrgQuery, [organizationName], (err, result) => {
          if (err) {
              console.error('Error checking organization name:', err);
              req.flash('error', 'There was an error checking the organization name.');
              return res.redirect('/create_org');
          }

          if (result.length > 0) {
              // If organization name already exists
              req.flash('error', 'An organization with this name already exists. Please choose a different name.');
              return res.redirect('/create_org');
          }

          // Insert the organization into the database
          const insertOrgQuery = 'INSERT INTO organizations (name) VALUES (?)';
          db.execute(insertOrgQuery, [organizationName], (err, result) => {
              if (err) {
                  console.error('Error inserting organization:', err);
                  req.flash('error', 'There was an error creating the organization.');
                  return res.redirect('/create_org');
              }

              const organizationId = result.insertId; // Get the ID of the newly created organization

              // Insert the user as an admin into the organization_users table
              const insertUserQuery = 'INSERT INTO organization_users (first_name, last_name, email, phone_number, isAdmin, organization_id) VALUES (?, ?, ?, ?, 1, ?)';
              db.execute(insertUserQuery, [firstName, lastName, userEmail, phoneNumber, organizationId], (err, result) => {
                  if (err) {
                      console.error('Error inserting user into organization_users:', err);
                      req.flash('error', 'There was an error adding you to the organization.');
                      return res.redirect('/create_org');
                  }

                  // Pass the success message to flash
                  req.flash('success', 'Organization created successfully, and you have been added as an admin.');
                  return res.redirect('/create_org');
              });
          });
      });
  });
});



const port = 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
