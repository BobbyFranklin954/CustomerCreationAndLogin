// Importing necessary libraries and modules
require('dotenv').config();
const path = require('path');
const mongoose = require('mongoose');            // MongoDB ODM library
const Customers = require(path.join(__dirname, '..', 'customer'));         // Imported MongoDB model for 'customers'
const express = require('express');              // Express.js web framework
const session = require('express-session');
const bodyParser = require('body-parser');       // Middleware for parsing JSON requests
const bcrypt = require("bcrypt")
const saltRounds = 5
const winston = require('winston');

const app = express();
const port = 3000;
//Generate a unique session id
const uuid = require('uuid');

app.use(session({
    cookie: { maxAge: 120000 }, // Session expires after 2 minutes of inactivity
    secret: process.env.SESSION_SECRET,
    res: false,
    saveUninitialized: true,
    genid: () => uuid.v4()
}));

// Create a logger
const logger = winston.createLogger({
    level: 'info', // Log level
    format: winston.format.json(), // Log format
    transports: [
        // Console transport
        new winston.transports.Console(),
        // File transport
        new winston.transports.File({ filename: 'logfile.log' }),
    ],
});

const uri = `mongodb://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_URI}?authSource=admin`;
mongoose.connect(uri, { 'dbName': 'customerDB' });
//mongoose.connect(uri, { 'dbName': 'customerDB' });

// Middleware to parse JSON requests
app.use("*", bodyParser.json());

// Serving static files from the 'frontend' directory under the '/static' route
app.use('/static', express.static(path.join(".", 'frontend')));

// Middleware to handle URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));

// POST endpoint for user login
app.post('/api/login', async (req, res) => {
    const data = req.body;
    // console.log(data);
    let user_name = data['user_name'];
    let password = data['password'];

    // Querying the MongoDB 'customers' collection for matching user_name and password
    const user = await Customers.findOne({ user_name: data['user_name'] });
    // console.log('Password entered:', password); // Plaintext password from login

    if (!user) {
        logger.error(`Login failed: User ${user_name} not found`); // Log error
        return res.status(404).send('User Information incorrect'); // User not found
    }
    if (!user.password) {
        logger.error(`Login failed: Password not found for user ${user_name}`); // Log error
        return res.status(500).send('Server error: Password not found for user');
    }
    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
        const genidValue = req.sessionID; // Assuming session middleware is active
        res.cookie('username', user_name);
        logger.info(`User ${user_name} logged in successfully with session ID: ${genidValue}`); // Log successful login
        res.status(200).redirect('/static/home.html'); // Redirect to the home page
        // res.status(200).send('Login successfully');
    } else {
        logger.error(`Login failed: Incorrect password for user ${user_name}`); // Log error
        res.status(401).send('Password Incorrect! Try again');
    }
});

// POST endpoint for adding a new customer
app.post('/api/add_customer', async (req, res) => {
    const data = req.body;
    console.log(data)
    const documents = await Customers.find({ user_name: data['user_name'] });
    if (documents.length > 0) {
        return res.send("User already exists");
    }

    let hashedpwd = bcrypt.hashSync(data['password'], saltRounds)

    // Creating a new instance of the Customers model with data from the request
    const customer = new Customers({
        "user_name": data['user_name'],
        "age": data['age'],
        "password": hashedpwd,
        "email": data['email']
    });

    // Saving the new customer to the MongoDB 'customers' collection
    await customer.save();

    res.send("Customer added successfully")
});

// GET endpoint for user logout
app.get('/api/logout', async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        } else {
            res.cookie('username', '', { expires: new Date(0) });
            res.redirect('/');
        }
    });
});

// GET endpoint for the root URL, serving the home page
app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'home.html'));
});

// Starting the server and listening on the specified port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});