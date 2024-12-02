# Overview
The purpose of this program is to provide an open-source web application that can Create Read Update and Delete for the purpose of work scheduling. 

# Calendar JS Documentation:
** This is the link to Calendar JS' documentation ** [Calendar.js](https://calendar-js.com/documentation/index.html)

# How to Get Started
First, this code will be run through visual studio code using express along with some other extensions.
## Setting up VSCode
### Installing Node.js
You will need to have node.js on your computer for this program to work.  
Follow this link and download the installer for node.js: [Node.js Installer](https://nodejs.org/en/download/prebuilt-installer)
### Git Bash Terminal
The first thing that you need to do is make sure that the default terminal you are using is the bash terminal, to do this press F1 or Fn + F1, and type  
`Terminal: Select Default Profile (or Terminal: Select Default Shell in older Visual Studio Code versions).`  
After pressing enter select the Git Bash option. You can then click the terminal option near the bottom of the screen and use the + button to add a bash terminal that is used to run our program
### Neccesary Extensions
For this you will need to install extensions onto your VSCode by either pressing `Ctrl + Shift + X` or by clicking the extensions icon on the left side of the terminal (Four square blocks with the top right one disconnected).  
Now install these extensions, EJS language support, HTML CSS support, JavaScript, JavaScript (ES6) code snippets, and Start git-bash  
![Screenshot 2024-11-28 231830](https://github.com/user-attachments/assets/04226e51-7883-444a-9a81-1a92a0d751ee)  
You will also need to use express with this program which can easily be installed through the bash terminal, by using the command: `npm install express`  

### Duplicating the Github
Now you can duplicate this github and its files into your VSCode by navigating to the file section at the top right of VSCode and clicking `Duplicate Workspace` You will then click 
`Clone Git Repository...` which will allow you to enter the link to this github: https://github.com/JCarey5/CS3300-Final-Project  

### Other Necessary Commands
From the bash terminal you must run these commands before attempting to run the program:  
```
npm install express passport passport-local express-session body-parser ejs
npm install connect-flash
npm install --save-dev nodemon
npm install mysql2
npm install jcalendar.js
``` 

## MySql Prep
### Install MySql
Follow this link [MySql](https://dev.mysql.com/downloads/installer/) to the MySql page and use the download button for Windows (x86, 32-bit), MSI Installer, this is the one with 306.5M downloads and this tag (mysql-installer-community-8.0.40.0.msi)
You will then follow the installer, downloading the server version of mysql2 onto your computer and setting the root password as you would like.
### Set Up MySql and Database
Now you must go to the MySql Command line that is now included on your machine and run these commands to set up the Database and tables:
```
CREATE DATABASE userDB;

USE userDB;


CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) DEFAULT NULL,
    organization VARCHAR(100) DEFAULT NULL,
    organization_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    event_data LONGTEXT DEFAULT NULL
);
CREATE TABLE organizations (
    organization_id VARCHAR(255) PRIMARY KEY,
    organization_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT,
    start_date DATETIME,
    end_date DATETIME,
    request_type VARCHAR(255),
    status ENUM('Pending', 'Approved', 'Denied'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_employee_id FOREIGN KEY (employee_id) REFERENCES users(id)
) ENGINE=InnoDB;
```
### Explanation of MySQL
```
CREATE DATABASE userDB;
USE userDB;
```
- Purpose: The userDB database is used to manage users, organizations, and requests in an organizational system.
- Database Context: All tables and operations in the following sections apply to the userDB database.

```
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) DEFAULT NULL,
    organization VARCHAR(100) DEFAULT NULL,
    organization_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    event_data LONGTEXT DEFAULT NULL
);
```
- id (INT): The unique identifier for each user. This is an auto-incrementing field, meaning it automatically increments when a new user is created.
- first_name (VARCHAR(50)): The first name of the user. Cannot be NULL.
- last_name (VARCHAR(50)): The last name of the user. Cannot be NULL.
- email (VARCHAR(100)): The email address of the user. This field must be unique, meaning no two users can share the same email address. Cannot be NULL.
- password (VARCHAR(255)): The password of the user, stored as a hashed string (recommended length for hashing). Cannot be NULL.
- organization_id (VARCHAR(255)): An optional field that links the user to a specific organization. This can be NULL if the user is not associated with any organization.
- organization (VARCHAR(100)): The name of the organization the user belongs to. This is an optional field and can be NULL.
- organization_admin (BOOLEAN): A flag indicating whether the user is an administrator for the organization. Default value is FALSE.
- created_at (TIMESTAMP): The timestamp of when the user was created. Automatically set to the current timestamp when the user is inserted.
- updated_at (TIMESTAMP): The timestamp of when the user record was last updated. This value automatically updates whenever the record is modified.
- event_data (LONGTEXT): An optional field to store any event-related data as long text. Can be NULL.

```
CREATE TABLE organizations (
    organization_id VARCHAR(255) PRIMARY KEY,
    organization_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```
- organization_id (VARCHAR(255)): The unique identifier for each organization. This serves as the primary key for the table.
- organization_name (VARCHAR(100)): The name of the organization. Cannot be NULL.
- created_at (TIMESTAMP): The timestamp when the organization was created. Automatically set to the current timestamp when the organization is inserted.
- updated_at (TIMESTAMP): The timestamp of the last update made to the organization record. This value automatically updates whenever the record is modified.

```
CREATE TABLE requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT,
    start_date DATETIME,
    end_date DATETIME,
    request_type VARCHAR(255),
    status ENUM('Pending', 'Approved', 'Denied'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_employee_id FOREIGN KEY (employee_id) REFERENCES users(id)
) ENGINE=InnoDB;
```
- id (INT): The unique identifier for each request. This is an auto-incrementing field.
- employee_id (INT): The ID of the user (employee) making the request. This is a foreign key that references the id column in the users table. The employee_id must match a valid user ID.
- start_date (DATETIME): The start date and time of the requested event or action.
- end_date (DATETIME): The end date and time of the requested event or action.
- request_type (VARCHAR(255)): The type of request being made (e.g., "Vacation", "Leave", etc.).
- status (ENUM): The status of the request, which can be one of the following: 'Pending', 'Approved', or 'Denied'. This field allows these three predefined values only.
- created_at (TIMESTAMP): The timestamp when the request was created. Automatically set to the current timestamp when the request is inserted.
- updated_at (TIMESTAMP): The timestamp when the request record was last updated. This value automatically updates whenever the record is modified.
- CONSTRAINT fk_employee_id: A foreign key constraint that ensures the employee_id in the requests table corresponds to a valid id in the users table.

## Running the Program
Now that you have set up your VSCode and MySQL, the program can be run simply by entering the command `npm run devStart` within the VSCode bash terminal and navigating to the appropriate local host
which in this case is `http://localhost:3000/` by default.



# Documentation
### Tech Stack:
CSS
HTML
JavaScript

### Frameworks:
Node.js
Express (built on Node.js)

### Tools:
Flash (Message Alert System)
Passport (Mini-Framework)

### Database:
MySQL version 8.0.40.0 (as of December 1, 2024)


## Code Structure and Organization
### Tech Stack Structure
```
User Request
     |
     v
  Node.js
  (Runtime Environment)
     |
     v
  Express.js
  (Web Framework)
     |
     v
Middleware Chain
  - Passport.js (Authentication Middleware)
  - Flash.js (Message Handling)
     |
     v
Server Response
 (Authenticated result, Flash message)
```

### Organization of Files
```
Project/
│
├── app.js         // Main application file
│
├── config/
│   ├── passport.js // Passport strategies and configuration
│   └── db.js       // Database connection settings
│
├── routes/    // *** These routes are contained inside of app.js ***
│   ├── index.js    // Home and general routes
│   ├── auth.js     // Authentication-related routes (login, signup, logout)
│   └── user.js     // User-related routes (profile, settings)
│
├── views/
│   ├── EJS files
│
├── public/
│   ├── css/       // Stylesheets
│   ├── js/        // Client-side scripts
│   └── images/    // Static assets
│
├── middleware/
│   ├── auth.js    // Middleware for authentication checks
│   ├── flash.js   // Middleware for integrating flash messages
│   └── error.js   // Middleware for error handling
│
├── package.json   // Project dependencies and scripts
├── .env           // Environment variables (e.g., database URI, session secrets)
└── README.md      // Project documentation
```


# Code Prologue:
> [!IMPORTANT]
> Key information users need to understand how this program was setup.

### Importing Modules:
```
const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const expressSession = require('express-session');
const bodyParser = require('body-parser');
const connectFlash = require('connect-flash');
const bcrypt = require('bcryptjs'); // For hashing passwords
const db = require('./db'); // Import the database connection
const app = express();

```
- express: Initializes an Express application (app).
- passport: Used for handling user authentication.
- LocalStrategy: A Passport strategy for username and password authentication.
- express-session: A middleware for managing session data.
- body-parser: Parses incoming request bodies (especially form data).
- connect-flash: Provides a way to pass flash messages (e.g., error or success messages) between routes.
- bcryptjs: A library for securely hashing passwords.
- db: Custom database module.

### Static File Handling:
```
app.use(express.static(__dirname + '/public'));
app.use(express.json());

```
- express.static: Serves static files (e.g., images, CSS, JS) from the public directory.
- express.json: Middleware to parse incoming JSON data.

### Passport Setup:
```
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  (email, password, done) => {
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) return done(err);

      if (results.length === 0) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      const user = results[0];

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
```
- passport.use(new LocalStrategy(...)): Configures Passport to use the Local strategy, with email as the usernameField.
- db.query: Queries the database to find the user based on the email provided.
- bcrypt.compare: Compares the entered password with the hashed password stored in the database.
- done: Callback function called when authentication succeeds or fails.

### Serialization and Deserialization:
```
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

```
- passport.serializeUser: Serializes the user into the session. Here, it stores the user's id.
- passport.deserializeUser: Deserializes the user from the session using the id, and retrieves user data from the database.

### Middleware Setup:
```
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressSession({ secret: 'secret-key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(connectFlash());
app.set('view engine', 'ejs');
```
- bodyParser.urlencoded: Middleware to parse URL-encoded data (like form submissions).
- expressSession: Middleware for session management. The secret is used to sign the session ID cookie, ensuring its integrity.
- resave: Whether to save the session even if it wasn't modified.
- saveUninitialized: Whether to save a session that is new but not modified.
- passport.initialize(): Initializes Passport to handle authentication.
- passport.session(): Handles persistent login sessions.
- connectFlash: Adds support for flash messages (usually for notifications like errors or success).
- app.set('view engine', 'ejs'): Sets EJS as the templating engine for rendering views.


# API
## Login and Register
```
app.get('/', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

```
- GET /: This route handles rendering the login form.
- req.flash('error'): Retrieves any error messages stored in the session, passed from previous requests, such as failed login attempts.
- res.render('login'): Renders the login.ejs view and passes the message object to it (for displaying flash messages).

```
POST /login: This route handles the form submission for user login.
passport.authenticate('local', ...): Uses Passport’s local authentication strategy to authenticate the user with the email and password.
successRedirect: '/manager_dashboard': Redirects the user to the /manager_dashboard route if the login is successful.
failureRedirect: '/': Redirects the user back to the login page if authentication fails.
failureFlash: true: Flash an error message if authentication fails, which will be shown on the login page.
```
- POST /login: This route handles the form submission for user login.
- passport.authenticate('local', ...): Uses Passport’s local authentication strategy to authenticate the user with the email and password.
  - successRedirect: '/manager_dashboard': Redirects the user to the /manager_dashboard route if the login is successful.
  - failureRedirect: '/': Redirects the user back to the login page if authentication fails.
  - failureFlash: true: Flash an error message if authentication fails, which will be shown on the login page.
 
```
app.post('/login', passport.authenticate('local', {
  successRedirect: '/manager_dashboard',
  failureRedirect: '/',
  failureFlash: true
}));
```
- GET /register: This route handles rendering the registration form.
- req.flash('error'): Passes any error messages stored in the session to the register view.
- res.render('register'): Renders the register.ejs view and passes the message object for error display.

```
app.post('/register', (req, res) => {
  const { first_name, last_name, email, password, confirm_password } = req.body;

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

      // Insert user data into the database with organization and organization_admin set to NULL
      const newUser = {
        first_name,
        last_name,
        email,
        password: hashedPassword,
        organization_id: null,  // organization_id set to NULL
        organization: null,  // organization set to NULL
        organization_admin: null // organization_admin set to NULL
      };

      db.query('INSERT INTO users SET ?', newUser, (err, result) => {
        if (err) throw err;
        req.flash('success', 'Registration successful! You can log in now.');
        return res.redirect('/');
      });
    });
  });
});

```
- POST /register: This route handles the form submission for user registration.
- Field Validation:
  - Check for empty fields: Ensures that all fields (first name, last name, email, password, confirm password) are filled in. If not, it flashes an error message and redirects back to the registration page.
  - Password Match: Checks if the password and confirm_password fields match. If they don't, an error message is flashed.
  - Email Validation: Uses a regular expression to check if the entered email is in a valid format. If not, an error message is flashed.
- Email Uniqueness Check:
  - db.query('SELECT * FROM users WHERE email = ?'): Queries the database to see if the email already exists. If the email is found, it flashes an error and redirects the user back to the registration page.
- Password Hashing:
  - bcrypt.hash(password, 10): Hashes the password with a salt rounds value of 10 before saving it to the database.
- Database Insertion:
  - db.query('INSERT INTO users SET ?', newUser): Inserts the new user data into the users table, with organization_id, organization, and organization_admin set to NULL.
- Flash Success: If the registration is successful, a success message is flashed, and the user is redirected to the login page.

## Dashboard
> [!IMPORTANT]
> The name "Manager_Dashboard" is not specific to each user. This was a mistake and is used for both admins and non-admins.

```
app.get('/manager_dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    const userFirstName = req.user ? req.user.first_name : null;
    const userOrganization = req.user ? req.user.organization : null;
    const userAdmin = req.user ? req.user.organization_admin : null;
    const user_id = req.user ? req.user.id : null;
    const userObject = {
      firstName: userFirstName,
      organization: userOrganization,
      isAdmin: userAdmin
    }
```
- app.get('/manager_dashboard'): This route is triggered when a user navigates to the /manager_dashboard URL.
- req.isAuthenticated(): Checks if the user is authenticated. If the user is not authenticated, they are redirected to the login page (/).
- User Object: Retrieves information about the logged-in user from the req.user object, including:
  - first_name: The user's first name.
  - organization: The user's associated organization.
  - organization_admin: A flag indicating whether the user is an admin of the organization.
  - id: The unique identifier of the logged-in user.
 
```
db.query('SELECT event_data FROM users WHERE id = ?', [user_id], (err, results) => {
  if (err) {
    console.error('Database query error:', err);
    return res.status(500).send('Internal server error'); // Handle errors gracefully
  }

  if (results.length === 0) {
    console.log('No data found for user id = 1');
    return res.status(404).send('No data found');
  }
```
- db.query('SELECT event_data FROM users WHERE id = ?', user_id, ...): This query retrieves the event_data field from the users table for the currently logged-in user. The user's ID (user_id) is used as a parameter to ensure the correct user's event data is fetched.
- Error Handling:
  - If there is a database query error (err), the server responds with a 500 status code and logs the error.
  - If no data is found for the user (results.length === 0), a 404 status code is returned with a message indicating no data was found.

```
var eventData = results[0].event_data;
const renderData = {
  ...userObject,
  eventData: eventData
};

try {
  // Render the page and pass the events data to the view
  res.render('ManagerDashBoard', renderData);
} catch (e) {
  console.error('Invalid JSON data:', e);
  res.status(400).send('Invalid JSON data in database');
}
```
- eventData: The event_data field from the database query result is extracted and stored in the eventData variable.
- renderData: Combines the userObject (which contains user-specific information) and the eventData into a single object, which will be passed to the view.
- res.render('ManagerDashBoard', renderData): The ManagerDashBoard view is rendered with the renderData object passed as data to the view. This object contains the user's information and their event data.
- Error Handling: If an error occurs while processing the event data (for example, if the data is not in a valid format), the server catches the error, logs it, and responds with a 400 status code indicating invalid JSON data.

```
} else {
  res.redirect('/');
}
```
- res.redirect('/'): If the user is not authenticated (i.e., req.isAuthenticated() is false), they are redirected to the login page (/).

## View Time-Off Requests
```
app.get('/view_requests', (req, res) => {
  if (req.isAuthenticated()) {
    const userOrganization = req.user ? req.user.organization : null;
    const isAdmin = req.user ? req.user.organization_admin : null;
    const user_id = req.user ? req.user.id : null;
    const userObject = {
      organization: userOrganization,
      isAdmin: isAdmin,
      user_id: user_id
    }
    
    if(isAdmin === 1)
    {
      db.query('SELECT * FROM requests WHERE status = ?', ['Pending'], (err, results) => {
        if (err) {
            console.error('Error fetching pending requests:', err);
            return res.status(500).send('Internal server error');
        }
        const renderData = {
          ...userObject,
          pendingRequests: results
        };
        console.log("array of results", results);
        res.render('view_requests', renderData);
      });
    }
    else{
      res.render('view_requests', userObject)
    }
  } else {
    res.redirect('/');
  }
})
```
- GET /view_requests: This route displays the time-off requests to users who are authenticated.
- req.isAuthenticated(): Checks if the user is authenticated. If the user is not authenticated, they are redirected to the login page (/).
- User Information: The following information is retrieved from req.user:
  - organization: The organization the user belongs to.
  - organization_admin: A flag indicating whether the user is an admin of the organization.
  - id: The unique identifier for the logged-in user.
- Admin Check:
  - If the user is an admin (isAdmin === 1), a query is made to the database to fetch all pending requests (requests with status = 'Pending').
  - Database Query:
    - db.query('SELECT * FROM requests WHERE status = ?', ['Pending']): This query retrieves all pending time-off requests from the requests table in the database.
  - Rendering the View:
    - If the user is an admin, the list of pending requests is passed to the view_requests template along with the user information (userObject).
  - If the user is not an admin, the view is rendered with only the user information (no pending requests).
- Error Handling:
 - If there is an error fetching the pending requests, a 500 status code is returned with a message indicating a server error.

```
app.post('/view_requests', (req, res) => {
  console.log("req body", req.body);
  const { startDate, endDate, requestType, employeeId } = req.body;

  const query = 'INSERT INTO requests (employee_id, start_date, end_date, request_type, status) VALUES (?, ?, ?, ?, ?)';
  const status = 'Pending'; 
  db.query(query, [employeeId, startDate, endDate, requestType, status], (err, result) => {
      if (err) {
          console.error('Error inserting request into the database:', err);
          return res.status(500).json({ message: 'Failed to submit time-off request.' });
      }

      res.status(200).json({ message: 'Time-off request submitted successfully!' });
  });
});
```
- POST /view_requests: This route handles the submission of new time-off requests by employees.
- Request Data:
  - The body of the request should contain the following fields:
    - startDate: The start date of the requested time off.
    - endDate: The end date of the requested time off.
    - requestType: The type of request (e.g., vacation, sick leave).
    - employeeId: The ID of the employee submitting the request.
- Database Query:
  - The request is inserted into the requests table in the database with a status of 'Pending'.
  - db.query('INSERT INTO requests ...'): Executes the insert operation with the provided data.
- Error Handling:
  - If an error occurs during the insertion, a 500 status code with an error message is returned.
  - If the request is successfully submitted, a 200 status code with a success message is returned.
 
```
app.post('/update-request-status', (req, res) => {
  const { id, status } = req.body;
  console.log(req.body);

  if (!id || !status) {
    return res.status(400).json({ message: 'Invalid request data.' });
  }

  const query = 'UPDATE requests SET status = ? WHERE id = ?';
  
  db.query(query, [status, id], (err, result) => {
    if (err) {
      console.error('Error updating request status:', err);
      return res.status(500).json({ message: 'Failed to update request status.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Request not found.' });
    }

    res.status(200).json({ message: 'Request status updated successfully!' });
  });
});
```
- POST /update-request-status: This route allows an admin to approve or deny time-off requests by updating the request's status in the database.
- Request Data:
  - The body of the request should contain:
    - id: The unique ID of the time-off request.
    - status: The new status for the request (e.g., 'Approved', 'Denied').
- Input Validation:
  - Checks if both id and status are provided. If either is missing, a 400 status code with a message indicating invalid request data is returned.
- Database Query:
  - db.query('UPDATE requests SET status = ? WHERE id = ?'): Updates the status of the specified request in the requests table based on its id.
- Error Handling:
  - If an error occurs during the update operation, a 500 status code with an error message is returned.
  - If the request is not found (i.e., no rows are affected), a 404 status code is returned.
  - If the status is updated successfully, a 200 status code with a success message is returned.


## Schedule Employee
```
app.get('/schedule_employee', (req, res) => {
  if (req.isAuthenticated()) {
    const user_id = req.user ? req.user.id : null;
    const isAdmin = req.user ? req.user.organization_admin : null;
    const organization = req.user ? req.user.organization : null;

    db.query('SELECT event_data FROM users WHERE id = ?', [user_id],  (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send('Internal server error');
      }

      if (results.length === 0) {
        console.log('No data found for user id = 1');
        return res.status(404).send('No data found');
      }

      var eventData = results[0].event_data;
  
      try {
        res.render('ScheduleEmployee', { isAdmin, organization, eventData: eventData });
      } catch (e) {
        console.error('Invalid JSON data:', e);
        res.status(400).send('Invalid JSON data in database');
      }
    });
  } else {
    res.redirect('/');
  }
});
```
- GET /schedule_employee: This route is used to display the schedule for a specific employee.
- Authentication Check:
  - req.isAuthenticated(): Ensures the user is logged in. If not, they are redirected to the login page (/).
- User Information:
  - user_id: The unique identifier of the logged-in user.
  - isAdmin: A flag indicating if the user is an admin within their organization.
  - organization: The organization the logged-in user belongs to.
- Database Query:
  - The query SELECT event_data FROM users WHERE id = ? retrieves the event_data for the logged-in user. This data is assumed to be JSON-formatted event data representing the user's schedule.
- Error Handling:
  - If no data is found for the user or if there's an error in the query, appropriate error messages are logged, and a status code (500 for server errors or 404 for no data) is returned.
- Render the Schedule:
  - If the event data is valid, the page is rendered with the user's schedule data (eventData). Admins also receive the isAdmin flag and organization information.

```
app.post('/schedule_employee', (req, res) => {
  const organization_id = req.user ? req.user.organization_id : null;

  db.query('SELECT id, first_name, last_name FROM users WHERE organization_id = ?', [organization_id], (err, results) => {
      if (err) {
          console.error('Database query error:', err);
          return res.status(500).send('Internal server error');
      }

      if (results.length === 0) {
          console.log('No data found for user id = 1');
          return res.status(404).send('No data found');
      }

      const employees = results.map(employee => {
          return {
              id: employee.id,
              fullName: `${employee.first_name} ${employee.last_name}`
          };
      });

      console.log('Employees:', employees);

      var eventJson = req.body;
      console.log('Event JSON:', eventJson);

      const userID = req.user.id;
      
      let adminEvents = [];

      employees.forEach(employee => {
        const employeeEvents = eventJson.filter(event => {
            return event.title && event.title.includes(employee.fullName);
        });

        const employeeEventData = JSON.stringify(employeeEvents);

        db.promise().execute(
            'UPDATE users SET event_data = ? WHERE id = ?',
            [employeeEventData, employee.id]
        )
        .then(() => {
            console.log(`Events for ${employee.fullName} successfully updated.`);
        })
        .catch(error => {
            console.error('Error exporting events for employee:', employee.fullName, error);
        });

        adminEvents = adminEvents.concat(employeeEvents);
        if (employeeEvents.length > 0) {
          console.log('Events found');
        } else {
            console.log(`No events found for ${employee.fullName}`);
        }
      });

      if (adminEvents.length > 0) {
        const adminEventData = JSON.stringify(adminEvents);

        db.query('SELECT id FROM users WHERE organization_id = ? AND organization_admin = ?', [organization_id, '1'], (err, adminResults) => {
            if (err) {
                console.error('Database query error for admins:', err);
                return res.status(500).send('Internal server error');
            }

            const adminPromises = adminResults.map(admin => {
                return db.promise().execute(
                    'UPDATE users SET event_data = ? WHERE id = ?',
                    [adminEventData, admin.id]
                );
            });

            Promise.all(adminPromises)
                .then(() => {
                    console.log('Admin event data successfully updated.');
                })
                .catch(error => {
                    console.error('Error exporting events to admins:', error);
                });
        });
    }

    res.status(200).json({ message: 'Events successfully exported to database!' });
  });
});
```
- POST /schedule_employee: This route is used by admins to submit and save the schedule for employees.
- Retrieve Employees:
  - The organization_id of the logged-in user is used to query the database and retrieve all employees within the same organization (SELECT id, first_name, last_name FROM users WHERE organization_id = ?).
  - Each employee is then mapped into an object containing their id and fullName.
- Event Data Processing:
  - req.body contains the event data (JSON format) that has been submitted via the calendar interface.
  - For each employee, the events are filtered based on whether the event title contains the employee's full name.
- Database Updates:
  - The event data for each employee is converted to JSON and stored in the event_data column of the users table using an UPDATE query.
- Admin Event Data:
  - If there are events to be updated for any employee, a combined list (adminEvents) of all events is prepared and stored for admin users as well.
  - A query is made to retrieve all admin users for the organization (organization_admin = 1) and update their event data in parallel.
- Error Handling:
  - If errors occur during the database queries or event updates, they are logged and a 500 status code is returned.
- Success Response:
  - If the event data is successfully updated for all employees and admins, a 200 status code with a success message is returned.

## Add Employee To Current Organization
```
app.get('/add_employee', (req, res) => {
  if (req.isAuthenticated()) {
    // Information directly sent to the front end to display user specific data
    const organization = req.user ? req.user.organization : null;
    const isAdmin = req.user ? req.user.organization_admin : null;
    res.render('add_employee', { isAdmin, organization, messages: req.flash() })
  } else {
    res.redirect('/');
  }
})
```
- Route Purpose: The GET route for /add_employee is used to render the page where an admin can add a new employee to their organization.
- Authentication Check:
  - req.isAuthenticated(): Verifies if the user is logged in. If the user is not authenticated, they are redirected to the home page (/).
- Data Sent to Frontend:
  - organization: The organization of the logged-in user.
  - isAdmin: Indicates whether the logged-in user is an admin within their organization.
  - messages: Flash messages that may contain error or success notifications.
- Rendering:
  - The add_employee view is rendered, with isAdmin, organization, and messages passed to the frontend for display.

```
app.post('/add_employee', (req, res) => {
  // Ensure the user is an authenticated admin
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    req.flash('error', 'You must be logged in to perform this action.');
    return res.redirect('/login');
  }

  const { email, makeAdmin } = req.body;
  const userId = req.user.id;

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
          const newOrganizationId = req.user.organization_id;

          // Step 2: Check if the user is already part of an organization
          if (userToAdd.organization_id) {
            req.flash('error', 'This user is already in an organization.');
            return res.redirect('/add_employee');
          }

          // Step 3: Add the user to the organization
          const organizationAdmin = makeAdmin === 'on' ? true : false;
          const organizationName = req.user.organization;

          // Update the user's organization details
          db.promise().execute(
            'UPDATE users SET organization_id = ?, organization = ?, organization_admin = ? WHERE id = ?',
            [newOrganizationId, organizationName, organizationAdmin, userToAdd.id]
          ).then(() => {
            req.flash('success', `User with email ${email} has been added to the organization.`);
            res.redirect('/add_employee');
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
```
- Route Purpose: The POST route for /add_employee is used to add a new employee to the logged-in admin’s organization.
- Authentication Check:
  - The code first checks if the user is logged in using req.isAuthenticated(). If not, a flash message is set and the user is redirected to the login page.
- Admin Check:
  - SELECT organization_admin FROM users WHERE id = ?: This query ensures that the logged-in user has admin privileges (organization_admin = 1). If the user is not an admin, an error message is set, and the user is redirected to the add employee page.
- Adding Employee Logic:
  - Step 1 - Check if User Exists:
    - A query is made to check if the user with the provided email exists in the database (SELECT id, organization_id FROM users WHERE email = ?). If no user is found, an error message is set, and the user is redirected back to the add employee page.
  - Step 2 - Check if User is Already in an Organization:
    - If the user already has an organization_id (i.e., they are part of another organization), an error message is set, and the user is redirected back to the add employee page.
  - Step 3 - Add the User to the Organization:
    - The user is added to the logged-in admin's organization (UPDATE users SET organization_id = ?, organization = ?, organization_admin = ? WHERE id = ?).
    - If the makeAdmin checkbox is checked, the new user is made an admin in the organization.
    - Flash messages are used to notify success or failure, and the user is redirected to the /add_employee page.
- Error Handling:
  - Throughout the code, errors are caught in .catch() blocks, and appropriate flash error messages are set to provide feedback to the user. Any issues, such as failing to fetch user data or update the organization, result in a redirection to the add employee page with an error message.
- Flash Messages:
  - req.flash('error', 'message'): Used to store error messages for redirecting users with feedback.
  - req.flash('success', 'message'): Used to store success messages when an operation succeeds.

## Remove Employee From Current Organization
```
app.get('/remove_employee', (req, res) => {
  // Ensure the user is authenticated
  if (!req.isAuthenticated() || !req.user) {
    req.flash('error', 'You must be logged in to view employees.');
    return res.redirect('/');
  }

  const loggedInUserId = req.user.id; // Logged-in user’s ID (retrieved from session)
  const isAdmin = req.user ? req.user.organization_admin : null;

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
      }

      // Step 2: Search for all employees in the same organization
      db.promise().execute('SELECT id, first_name, last_name, email FROM users WHERE organization_id = ?', [organizationId])
        .then(([users]) => {
          if (users.length === 0) {
            req.flash('info', 'No employees found in your organization.');
            return res.render('remove_employee', { isAdmin, organization, employees: [], messages: req.flash() });
          }

          // Step 3: Render the employee list with a delete button
          res.render('remove_employee', { isAdmin, organization, employees: users, messages: req.flash() });
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
```
- Route Purpose: The GET route for /remove_employee retrieves a list of employees in the same organization as the logged-in user and displays them to the admin.
- Authentication Check:
  - req.isAuthenticated(): Checks if the user is logged in. If not, a flash error message is set, and the user is redirected to the homepage (/).
- Step 1 - Fetch User’s Organization:
  - A query is executed to fetch the organization_id of the logged-in user from the database.
- Step 2 - Fetch Employees:
  - Once the organization is identified, a second query fetches all users who belong to the same organization. The list of employees (if any) is then rendered to the page.
- Error Handling:
  - Errors are caught and logged using .catch(). Flash messages are set, and the user is redirected to the /remove_employee page if any issues arise.
- Rendering:
  - If employees are found, the list is rendered in the remove_employee view, with each employee’s details and a delete button to remove them from the organization.
  - If no employees are found or there is an error, an appropriate flash message is displayed.

```
app.post('/remove_employee/:id', (req, res) => {
  const employeeId = req.params.id; // Get the employee's ID to be removed
  const loggedInUserId = req.user.id; // Logged-in user’s ID

  // Step 1: Fetch the logged-in user's organization_id to see if they're in an organization
  db.promise().execute('SELECT organization_id FROM users WHERE id = ?', [loggedInUserId])
    .then(([rows]) => {
      if (rows.length === 0) {
        req.flash('error', 'User not found.');
        return res.redirect('/dashboard');
      }

      const organizationId = rows[0].organization_id; // The logged-in user's organization_id

      if (!organizationId) {
        req.flash('error', 'You are not assigned to any organization.');
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
```
- Route Purpose: The POST route for /remove_employee/:id is responsible for removing an employee from the organization when the admin selects an employee to remove.
- Step 1 - Fetch User’s Organization:
  - The organization_id of the logged-in user is retrieved to confirm their membership in an organization.
- Step 2 - Check If Employee is the Last One:
  - A query counts the number of employees in the organization. If the count is 1, it deletes the organization itself along with the employee.
  - If there are multiple employees, only the selected employee is removed from the organization, and their organization_id and organization_admin status are set to NULL and FALSE, respectively.
- Step 3 - Deleting Organization (If Last Employee):
  - If the employee is the last member of the organization, the organization is deleted, and the employee is removed.
- Error Handling:
  - Errors that occur at any stage (fetching user details, checking employee count, deleting organization, etc.) are logged and handled by displaying an appropriate flash message.
- Flash Messages:
  - req.flash('success', 'message'): Used to notify the admin of a successful operation.
  - req.flash('error', 'message'): Used to notify the admin of any errors.
  - req.flash('info', 'message'): Used to notify the admin if no employees are found.

## View Employees in Current Organization
```
app.get('/view_employee', (req, res) => {

  if (req.isAuthenticated()) {
    // Information directly sent to the front end to display user specific data
    const loggedInUserId = req.user.id; 
    const isAdmin = req.user ? req.user.organization_admin : null;

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
        }

        // Step 2: Search for all employees in the same organization
        db.promise().execute('SELECT first_name, last_name, email FROM users WHERE organization_id = ?', [organizationId])
          .then(([users]) => {
            if (users.length === 0) {
              req.flash('info', 'No employees found in your organization.');
              return res.render('view_employee', { isAdmin, organization, employees: [], 
                messages: req.flash()
              });
            }

            // Step 3: Render the employees' list in the view
            res.render('view_employee', { isAdmin, organization, employees: users,
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
  } else {
    res.redirect('/');
  }
});
```
- User Authentication Check:
  - req.isAuthenticated(): Checks if the user is logged in. If not, they are redirected to the homepage (/).
- Step 1 - Fetch User's Organization:
  - A query is executed to fetch the organization_id for the logged-in user.
  - If the user is not found or not assigned to any organization, an error message is set using req.flash('error', 'message').
- Step 2 - Fetch Employees in the Same Organization:
  - Once the organization ID is retrieved, another query is made to fetch all employees associated with that organization.
  - If no employees are found, an informational message (No employees found in your organization.) is displayed.
- Step 3 - Render the View:
  - If employees are found, the view_employee template is rendered with the list of employees and their details (first name, last name, email).
  - The isAdmin variable is passed to the view to indicate if the logged-in user is an admin.
  - Flash messages are included in the render to show any alerts or notifications (success, error, info).
- Error Handling:
  - Errors during the database queries are logged to the console, and appropriate flash messages are set.
  - In case of an error fetching user details or employees, the user is redirected back to the /view_employee route with an error message.

## Create an Organization
```
app.get('/create_org', (req, res) => {
  const isAdmin = req.user ? req.user.organization_admin : null;
  if (req.isAuthenticated()) {
    res.render('create-organization', {isAdmin, info: req.flash()})
  } else {
    res.redirect('/');
  }
})
```
- Authentication Check: The route first checks if the user is authenticated using req.isAuthenticated(). If the user is not logged in, they are redirected to the homepage (/).
- Render Create Organization Page: If the user is logged in, the create-organization view is rendered with two pieces of data:
  - isAdmin: Indicates whether the logged-in user is an admin (this value is retrieved from the session).
  - info: Contains any flash messages (error or success) to display to the user.

```
app.post('/create_org', async (req, res) => {
  if (!req.isAuthenticated()) {
      return res.redirect('/login');  // Check authentication within POST route body
  }

  // Store session user info
  const organizationName = req.body.organization_name;
  const userId = req.user.id; 

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
```
- Authentication Check:
  - If the user is not authenticated, they are redirected to the login page. This check is done right at the start of the POST request.
- Capture User Input:
  - organizationName: The name entered by the user for the new organization.
  - userId: The ID of the logged-in user (retrieved from the session).
- Organization Name Validation:
  - The organization name is checked for being empty or blank. If it is, a flash message is displayed to inform the user, and the user is redirected back to the /create_org route.
- Check if User Already Belongs to an Organization:
  - A query checks if the logged-in user is already assigned to an organization by looking up their organization_id in the users table.
  - If the user is already part of an organization, a flash error message is shown, and the user is redirected to the /create_org route.
- Check for Existing Organization:
  - A query checks if an organization with the same name already exists in the organizations table.
  - If an organization with the same name exists, an error message is displayed, and the user is redirected back to the /create_org page.
- Create New Organization:
  - If the above checks pass, a new organization is created by:
    - Generating a unique organization ID (organizationId is created using the current timestamp).
    - Inserting the new organization into the organizations table.
    - Updating the users table to link the logged-in user to the newly created organization, and marking the user as an admin of that organization.
- Success and Error Handling:
  - If all steps are successful, a success message is displayed using req.flash('success', ...), and the user is redirected back to the /create_org page.
  - If any error occurs during the process (such as issues with database queries), an error message is displayed using req.flash('error', ...), and the user is redirected back to the /create_org page.


## Logging-Out
```
app.get('/logout', (req, res) => {
  req.logout((err) => {
      if (err) return next(err);
      res.redirect('/');
  });
});
```
- Request Type: GET
  - This route is triggered when a user sends a GET request to /logout, typically by clicking a "Logout" button or link.
- req.logout() Method:
  - This method is part of the passport.js authentication middleware. It is used to terminate the current user session.
  - It removes the user from the session and invalidates any authentication state, effectively logging the user out.
- Error Handling:
  - If an error occurs during the logout process, it is passed to the next middleware with return next(err).
  - The next function is used to forward any errors to the error-handling middleware in the application.
- Redirect After Logout:
  - After successfully logging out, the user is redirected to the homepage (/).
  - This is typically done to ensure the user is taken to a neutral page (like the homepage) after their session ends.

# Database JS Side
```
const mysql = require('mysql2');
```
- The code imports the mysql2 library, which provides support for MySQL operations in Node.js.

```
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'userDB'
});
```
- Database Connection Configuration:
  - The mysql.createConnection method is used to set up a connection to the database.
  - Configuration parameters include:
    - host: The hostname of the database server (e.g., localhost).
    - user: The username to authenticate with the database.
    - password: The password for the provided username.
    - database: The specific database to use on the server.

```
db.connect((err) => {
  if (err) {
    console.error('Could not connect to MySQL:', err);
    process.exit(1);
  } else {
    console.log('Connected to MySQL database');
  }
});
```
- The db.connect method initiates the connection.
- If an error occurs during the connection attempt, it logs the error and exits the process with an error status code.
- If successful, it logs a success message.

```
module.exports = db;
```
- The db object is exported for reuse across other parts of the application. This allows modules like route handlers or controllers to interact with the database.


# package.json
```
{
  "name": "test",
  "version": "1.0.0",
  "author": "",
  "license": "ISC",
  "description": ""
}

```
- name: The name of the project, in this case, "test".
- version: The version of the project, set to "1.0.0".
- description: A brief description of the project (currently empty).
- author: The author's name or contact information (currently empty).
- license: Specifies the license under which the project is distributed, set to "ISC".
```
"main": "index.js"

```
- main: Specifies the main entry point of the project, which is "index.js" by default.
```
"scripts": {
  "start": "node app.js",
  "devStart": "nodemon app.js"
}

```
start: Runs the project using node app.js.
devStart: Runs the project using nodemon app.js, enabling automatic restarts on file changes.
```
"dependencies": {
  "bcryptjs": "^2.4.3",
  "body-parser": "^1.20.3",
  "connect-flash": "^0.1.1",
  "ejs": "^3.1.10",
  "express": "^4.21.1",
  "express-session": "^1.18.1",
  "jcalendar.js": "^2.12.1",
  "mysql2": "^3.11.4",
  "passport": "^0.7.0",
  "passport-local": "^1.0.0"
}

```
- Lists the required packages for the project, installed using npm install. These packages are necessary for the app to function.
- Dependencies:
  - bcryptjs: For hashing passwords securely.
  - body-parser: To parse incoming request bodies.
  - connect-flash: For flash message handling.
  - ejs: Template engine for rendering views.
  - express: Web application framework.
  - express-session: Session management middleware.
  - jcalendar.js: For calendar-related functionality.
  - mysql2: For connecting and querying a MySQL database.
  - passport: Authentication middleware.
  - passport-local: Passport strategy for username/password authentication.
```
"devDependencies": {
  "dotenv": "^16.4.5",
  "nodemon": "^3.1.7"
}

```
- These packages are only used during development:
  - dotenv: Loads environment variables from a .env file.
  - nodemon: Automatically restarts the app when file changes are detected.


# Future of this Project
This project can be downloaded, modified, and redistributed to anyone. Any features to be added to existing or future ones. Any existing code can be modified as long as the correct changes are made to the MySQL server and any full stack code.











