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

## Running the Program
Now that you have set up your VSCode and MySQL, the program can be run simply by entering the command `npm run devStart` within the VSCode bash terminal and navigating to the appropriate local host
which in this case is `http://localhost:3000/` by default.
