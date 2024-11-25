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
        organization_admin: null // organizationAdmin set to NULL
      };

      db.query('INSERT INTO users SET ?', newUser, (err, result) => {
        if (err) throw err;
        req.flash('success', 'Registration successful! You can log in now.');
        return res.redirect('/');
      });
    });
  });
});




app.get('/manager_dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    const userFirstName = req.user ? req.user.first_name : null;
    const userOrganization = req.user ? req.user.organization : null;
    const userObject = {
      firstName: userFirstName,
      organization: userOrganization
    }
    res.render('ManagerDashBoard', userObject)
    
  } else {
    res.redirect('/');
  }
})


app.get('/schedule_employee', (req, res) => {
  if (req.isAuthenticated()) {
    const organization_id = req.user ? req.user.organization_id : null;
    console.log(organization_id)
    const organization = req.user ? req.user.organization : null;

    db.query('SELECT event_data FROM users WHERE organization_id = ?', [organization_id],  (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send('Internal server error'); // Handle errors gracefully
      }

      if (results.length === 0) {
        console.log('No data found for user id = 1');
        return res.status(404).send('No data found');
      }
      // Assuming events_data is the BLOB column
      var eventData = results[0].event_data;
      
      // Convert BLOB binary data to string
      //var jsonData = JSON.parse(eventData);
      //console.log(jsonData);
      

      // Parse JSON if it's valid JSON data
      try {
        
        //console.log(events); // Now you have the events data as a JSON object

        
        // Render the page and pass the events data to the view
        res.render('ScheduleEmployee', { organization, eventData: eventData });

      } catch (e) {
        console.error('Invalid JSON data:', e);
        res.status(400).send('Invalid JSON data in database');
      }
    }); 
    } else {
    res.redirect('/');
  }
})


app.get('/view_requests', (req, res) => {
  if (req.isAuthenticated()) {
    const userOrganization = req.user ? req.user.organization : null;
    const userObject = {
      organization: userOrganization
    }
    res.render('ViewEmployeeRequests', userObject)
    
  } else {
    res.redirect('/');
  }
})


app.get('/add_employee', (req, res) => {
  if (req.isAuthenticated()) {
    const organization = req.user ? req.user.organization : null;
    res.render('add_employee', { organization, messages: req.flash()})
    
  } else {
    res.redirect('/');
  }
})

app.use(bodyParser.json());
app.post('/schedule_employee', (req, res) => {
  // Assuming 'calendarInstance1' is your calendar instance
    // Retrieve all events from the calendar
    var eventJason = JSON.stringify(req.body);
    console.log(eventJason);
    
    const userID = req.user.id;
        
    

    // Send the event data to the server to store it in MySQL
    db.promise().execute(
        'UPDATE users SET event_data = ? WHERE id = ?',
        [eventJason, userID]
    )
    .then(() => {
      // On success, send a response back to the client
      res.status(200).json({ message: 'Events successfully exported to database!' });
     })
    .catch(error => {
      console.error('Error exporting events:', error);

      // Send a response with an error status and message
      res.status(500).json({ message: 'There was an error exporting events.', error: error.message });
    });

});

// POST route to add employee to an organization
app.post('/add_employee', (req, res) => {
  // Ensure the user is an authenticated admin
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    req.flash('error', 'You must be logged in to perform this action.');
    return res.redirect('/login'); // Redirect if not logged in
  }

  const { email, makeAdmin } = req.body;
  const userId = req.user.id; // Assuming `req.user.id` is the admin's ID (ensure passport is properly configured)

  // Ensure the logged-in user is an admin
  db.promise().execute('SELECT organization_admin FROM users WHERE id = ?', [userId])
    .then(([rows]) => {
      if (rows.length === 0 || !rows[0].organization_admin) {
        req.flash('error', 'You must be an admin to add employees to an organization.');
        return res.redirect('/add_employee');
      }

      // Step 1: Check if the user exists by email
      db.promise().execute('SELECT id, organization_id FROM users WHERE email = ?', [email])
        .then(([userRows]) => {
          if (userRows.length === 0) {
            req.flash('error', 'No user found with this email.');
            return res.redirect('/add_employee');
          }

          const userToAdd = userRows[0];
          const newOrganizationId = req.user.organization_id; // Get the admin's organization_id

          // Step 2: Check if the user is already part of an organization
          if (userToAdd.organization_id) {
            req.flash('error', 'This user is already in an organization.');
            return res.redirect('/add_employee');
          }

          // Step 3: Add the user to the organization
          const organizationAdmin = makeAdmin === 'on' ? true : false; // Make them an admin if checkbox is checked
          const organizationName = req.user.organization; // Admin's organization name

          // Update the user's organization details
          db.promise().execute(
            'UPDATE users SET organization_id = ?, organization = ?, organization_admin = ? WHERE id = ?',
            [newOrganizationId, organizationName, organizationAdmin, userToAdd.id]
          ).then(() => {
            req.flash('success', `User with email ${email} has been added to the organization.`);
            res.redirect('/add_employee'); //success
          }).catch(err => {
            console.error(err);
            req.flash('error', 'An error occurred while adding the user to the organization.');
            res.redirect('/add_employee');
          });
        }).catch(err => {
          console.error(err);
          req.flash('error', 'An error occurred while fetching the user.');
          res.redirect('/add_employee');
        });
    }).catch(err => {
      console.error(err);
      req.flash('error', 'An error occurred while checking admin rights.');
      res.redirect('/add_employee');
    });
});




// Route to render 'remove_employee' page and display employees
app.get('/remove_employee', (req, res) => {
  // Ensure the user is authenticated
  if (!req.isAuthenticated() || !req.user) {
    req.flash('error', 'You must be logged in to view employees.');
    return res.redirect('/');
  }

  const loggedInUserId = req.user.id; // Logged-in user’s ID (retrieved from session)

  // Step 1: Fetch the logged-in user's organization_id from the database
  db.promise().execute('SELECT organization_id FROM users WHERE id = ?', [loggedInUserId])
    .then(([rows]) => {
      if (rows.length === 0) {
        req.flash('error', 'User not found.');
        return res.redirect('/remove_employee');
      }

      const organizationId = rows[0].organization_id; // The logged-in user's organization_id
      const organization = req.user ? req.user.organization : null;
      


      if (!organizationId) {
        req.flash('error', 'You are not assigned to any organization.');
        return res.redirect('/remove_employee');
      }

      // Step 2: Search for all employees in the same organization
      db.promise().execute('SELECT id, first_name, last_name, email FROM users WHERE organization_id = ?', [organizationId])
        .then(([users]) => {
          if (users.length === 0) {
            req.flash('info', 'No employees found in your organization.');
            return res.render('remove_employee', { organization, employees: [], messages: req.flash()  });
          }

          // Step 3: Render the employee list with a delete button
          res.render('remove_employee', { organization, employees: users, messages: req.flash() });
        })
        .catch(err => {
          console.error(err);
          req.flash('error', 'An error occurred while fetching employees.');
          res.redirect('/remove_employee');
        });
    })
    .catch(err => {
      console.error(err);
      req.flash('error', 'An error occurred while fetching your organization.');
      res.redirect('/remove_employee');
    });
});

// Route to handle the removal of an employee
app.post('/remove_employee/:id', (req, res) => {
  const employeeId = req.params.id; // Get the employee's ID to be removed
  const loggedInUserId = req.user.id; // Logged-in user’s ID

  // Step 1: Fetch the logged-in user's organization_id
  db.promise().execute('SELECT organization_id FROM users WHERE id = ?', [loggedInUserId])
    .then(([rows]) => {
      if (rows.length === 0) {
        req.flash('error', 'User not found.');
        return res.redirect('/dashboard');
      }

      const organizationId = rows[0].organization_id; // The logged-in user's organization_id

      if (!organizationId) {
        req.flash('error', 'You are not assigned to any organization.');
        //return res.redirect('/dashboard');
      }

      // Step 2: Check if the user being deleted is the last employee in the organization
      db.promise().execute('SELECT COUNT(*) AS employeeCount FROM users WHERE organization_id = ?', [organizationId])
        .then(([countRows]) => {
          const employeeCount = countRows[0].employeeCount;

          // If this is the last employee, delete the organization
          if (employeeCount === 1) {
            // Step 3: Delete the organization
            db.promise().execute('DELETE FROM organizations WHERE id = ?', [organizationId])
              .then(() => {
                // Step 4: Remove the employee from the users table (their organization)
                db.promise().execute('UPDATE users SET organization_id = NULL, organization_admin = FALSE WHERE id = ?', [employeeId])
                  .then(() => {
                    req.flash('success', 'Employee and their organization have been deleted.');
                    res.redirect('/remove_employee');
                  })
                  .catch(err => {
                    console.error(err);
                    req.flash('error', 'An error occurred while removing the employee.');
                    res.redirect('/remove_employee');
                  });
              })
              .catch(err => {
                console.error(err);
                req.flash('error', 'An error occurred while deleting the organization.');
                res.redirect('/remove_employee');
              });
          } else {
            // If not the last employee, just remove the employee
            db.promise().execute('UPDATE users SET organization_id = NULL, organization_admin = FALSE WHERE id = ?', [employeeId])
              .then(() => {
                req.flash('success', 'Employee has been successfully removed from your organization.');
                res.redirect('/remove_employee');
              })
              .catch(err => {
                console.error(err);
                req.flash('error', 'An error occurred while removing the employee.');
                res.redirect('/remove_employee');
              });
          }
        })
        .catch(err => {
          console.error(err);
          req.flash('error', 'An error occurred while checking the employee count.');
          res.redirect('/remove_employee');
        });
    })
    .catch(err => {
      console.error(err);
      req.flash('error', 'An error occurred while fetching your organization.');
      res.redirect('/remove_employee');
    });
});




app.get('/view_employee', (req, res) => {

  if (req.isAuthenticated()) {
    //res.render('view_employee', {messages: req.flash()})

    const loggedInUserId = req.user.id; // Logged-in user’s ID (retrieved from session)
    

    // Step 1: Fetch the logged-in user's organization_id from the database
    db.promise().execute('SELECT organization_id FROM users WHERE id = ?', [loggedInUserId])
      .then(([rows]) => {
        if (rows.length === 0) {
          req.flash('error', 'User not found.');
          return res.redirect('/view_employee');
        }

        const organizationId = rows[0].organization_id; // The logged-in user's organization_id
        const organization = req.user ? req.user.organization : null;

        if (!organizationId) {
          req.flash('error', 'You are not assigned to any organization.');
          //return res.redirect('/view_employee');
        }

        // Step 2: Search for all employees in the same organization
        db.promise().execute('SELECT first_name, last_name, email FROM users WHERE organization_id = ?', [organizationId])
          .then(([users]) => {
            if (users.length === 0) {
              req.flash('info', 'No employees found in your organization.');
              return res.render('view_employee', { organization, employees: [], 
                messages: req.flash()
              });
            }

            // Step 3: Render the employees' list in the view
            res.render('view_employee', { organization, employees: users,
              messages: req.flash()
             });
          })
          .catch(err => {
            console.error(err);
            req.flash('error', 'An error occurred while fetching employees.');
            res.redirect('/view_employee');
          });
      })
      .catch(err => {
        console.error(err);
        req.flash('error', 'An error occurred while fetching your organization.');
        res.redirect('/view_employee');
      });
    }

    else 
    {
    res.redirect('/');
    } 

  
});







app.get('/create_org', (req, res) => {
  if (req.isAuthenticated()) {
    
    res.render('create-organization', {
      info: req.flash()})
    
  } else {
    res.redirect('/');
  }
})



// Form Validation Helper Function
const validateOrganizationName = (organizationName) => {
  const errors = [];
  if (!organizationName || organizationName.trim().length === 0) {
      errors.push('Organization name cannot be empty.');
  } else if (organizationName.length < 3) {
      errors.push('Organization name must be at least 3 characters long.');
  }
  return errors;
};



// Handle Organization Creation
app.post('/create_org', async (req, res) => {
  if (!req.isAuthenticated()) {
      return res.redirect('/login');  // Check authentication within POST route body
  }

  const organizationName = req.body.organization_name;
  const userId = req.user.id; // Assuming `req.user.id` is the user's ID (ensure passport is properly configured)

  console.log(organizationName)

  // Validate the organization name (simple check for empty string)
  if (!organizationName || organizationName.trim() === '') {
    req.flash('error', 'Organization name cannot be empty.');
    return res.redirect('/create_org');
  }

  try {
    // Step 1: Check if the user is already in an organization
    const [userRows] = await db.promise().execute('SELECT organization_id FROM users WHERE id = ?', [userId]);
    if (userRows.length > 0 && userRows[0].organization_id) {
      req.flash('error', 'You are already a member of an organization.');
      return res.redirect('/create_org');
    }

    // Step 2: Check if an organization with the same name already exists
    const [orgRows] = await db.promise().execute('SELECT organization_id FROM organizations WHERE organization_name = ?', [organizationName]);
    if (orgRows.length > 0) {
      req.flash('error', 'An organization with that name already exists.');
      return res.redirect('/create_org');
    }

    // Step 3: Create a new organization if both checks pass
    const organizationId = 'org-' + Date.now(); // Generate a unique organization ID
    await db.promise().execute('INSERT INTO organizations (organization_id, organization_name) VALUES (?, ?)', [organizationId, organizationName]);

    // Step 4: Update the user's organization fields
    await db.promise().execute('UPDATE users SET organization_id = ?, organization = ?, organization_admin = ? WHERE id = ?', [organizationId, organizationName, true, userId]);

    // Success: Flash success message and redirect to dashboard
    req.flash('success', 'Organization created successfully!');
    res.redirect('/create_org'); 

  } catch (err) {
    console.error(err);
    req.flash('error', 'There was an error while processing your request.');
    res.redirect('/create_org');
  }
});


// Log out route
app.get('/logout', (req, res) => {
  req.logout((err) => {
      if (err) return next(err);
      res.redirect('/');
  });
});


const port = 3000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
