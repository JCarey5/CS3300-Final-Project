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

  console.log(userEmail)
  console.log(organizationId)
  

  // Check if the logged-in user is an admin for the organization
  const checkAdminQuery = 'SELECT isAdmin FROM organization_users WHERE email = ? AND organization_id = ?';
  db.execute(checkAdminQuery, [userEmail, organizationId], (err, result) => {
      if (err) {
          console.error('Error checking admin status:', err);
          req.flash('error', 'There was an error verifying admin status.');
          return res.redirect('/add_employee');
      }

      
      const userEmailToAdd = req.body.email;  // The email of the user to add

      // Check if the user exists in the `users` table
      const checkUserQuery = 'SELECT * FROM users WHERE email = ?';
      db.execute(checkUserQuery, [userEmailToAdd], (err, result) => {
          if (err) {
              console.error('Error checking user existence:', err);
              req.flash('error', 'There was an error checking the user existence.');
              return res.redirect('/add_employee');
          }

          // If the user does not exist, show an error
          if (result.length === 0) {
              req.flash('error', 'User does not exist.');
              return res.redirect('/add_employee');
          }

          // Extract the user's details from the `users` table (based on the submitted email)
          const user = result[0];  // The user object returned from the query
          const firstName = user.first_name;
          const lastName = user.last_name;
          const phoneNumber = user.phone_number || null;  // Default to null if phone_number is missing

          // Check if the user is already in the organization
          const checkOrgUserQuery = 'SELECT * FROM organization_users WHERE email = ? AND organization_id = ?';
          db.execute(checkOrgUserQuery, [userEmailToAdd, organizationId], (err, result) => {
              if (err) {
                  console.error('Error checking if user is already in the organization:', err);
                  req.flash('error', 'There was an error checking if the user is already in the organization.');
                  return res.redirect('/add_employee');
              }

              // If the user is already in the organization, show an error
              if (result.length > 0) {
                  req.flash('error', 'User is already in this organization.');
                  return res.redirect('/add_employee');
              }

              // Check if the user is already part of another organization
              const checkOtherOrgQuery = 'SELECT * FROM organization_users WHERE email = ? AND organization_id != ?';
              db.execute(checkOtherOrgQuery, [userEmailToAdd, organizationId], (err, result) => {
                  if (err) {
                      console.error('Error checking if user is part of another organization:', err);
                      req.flash('error', 'There was an error checking if the user is part of another organization.');
                      return res.redirect('/add_employee');
                  }

                  // If the user is already in another organization, show an error
                  if (result.length > 0) {
                      req.flash('error', 'User is already part of another organization.');
                      return res.redirect('/add_employee');
                  }

                  // Insert the user into the `organization_users` table with appropriate details
                  const insertOrgUserQuery = 'INSERT INTO organization_users (first_name, last_name, email, phone_number, isAdmin, organization_id) VALUES (?, ?, ?, ?, 0, ?)';
                  db.execute(insertOrgUserQuery, [firstName, lastName, userEmailToAdd, phoneNumber, organizationId], (err, result) => {
                      if (err) {
                          console.error('Error adding user to organization:', err);
                          req.flash('error', 'There was an error adding the user to the organization.');
                          return res.redirect('/add_employee');
                      }

                      // Success message on successful insertion
                      req.flash('success', 'User added to the organization successfully.');
                      return res.redirect('/add_employee');
                  });
              });
          });
      });
  });
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
