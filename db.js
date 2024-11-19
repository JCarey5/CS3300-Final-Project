/*This file is only meant to connect to the mySQL database
*/



// db.js
const mysql = require('mysql2');

// Create a connection to the database
const db = mysql.createConnection({
  host: 'localhost',       // MySQL host
  user: 'root',            // MySQL username
  password: 'password',            // MySQL password
  database: 'userDB'       // MySQL database name
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error('Could not connect to MySQL:', err);
    process.exit(1);  // Exit the app if connection fails
  } else {
    console.log('Connected to MySQL database');
  }
});




// Export the database connection to be used in other files
module.exports = db;
