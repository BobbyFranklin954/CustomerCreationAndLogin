// Importing necessary libraries and modules
require('dotenv').config();
const path = require('path');
const mongoose = require('mongoose');            // MongoDB ODM library
const Customers = require(path.join(__dirname, '..', 'customer'));         // Imported MongoDB model for 'customers'
const express = require('express');              // Express.js web framework
const bodyParser = require('body-parser');       // Middleware for parsing JSON requests
const winston = require('winston');
const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken');  // Added JWT library
const saltRounds = 5
const usersTTL = 15 * 60 * 1000; // Set TTL (Time-to-Live) for users in memory (e.g., 15 minutes in milliseconds)


// Creating an instance of the Express application
const app = express();

// Setting the port number for the server
const port = 3000;

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

// A dictionary object to store username and password
let usersdic = {};

// MongoDB connection URI and database name
const uri = `mongodb://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_URI}?authSource=admin`;
mongoose.connect(uri, { 'dbName': 'customerDB' }); //mongoose.connect(uri, { 'dbName': 'customerDB' });

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

    const user_name = data['user_name'];
    const password = data['password'];

    let user = usersdic[user_name]; // Check in-memory users first

    if (!user) {
        // If not in memory, check MongoDB
        const document = await Customers.findOne({ user_name: user_name });
        if (document) {
            user = { hashedpwd: document.password };  // Fetch password from DB
        } else {
            logger.error(`Login failed: User ${user_name} not found`); // Log error
            return res.status(401).send('User Information incorrect');
        }
    }

    const result = await bcrypt.compare(password, user.hashedpwd);
    if (result) {
        const token = jwt.sign({ user_name: user_name }, process.env.SESSION_SECRET);
        logger.info(`User ${user_name} logged in successfully with token: ${token}`); // Log successful login
        res.status(200).redirect('/static/home.html'); // Redirect to the home page
    } else {
        logger.error(`Login failed: Incorrect password for user ${user_name}`); // Log error
        res.status(401).send('Password incorrect');
    }
});

// POST endpoint for adding a new customer
app.post('/api/add_customer', async (req, res) => {
    const data = req.body;
    console.log(data)

    const documents = await Customers.find({ user_name: data['user_name'] });
    if (documents.length > 0) {
        return res.status(409).send("User already exists");
    }

    const hashedpwd = await bcrypt.hash(data['password'], saltRounds);

    // Store in-memory with TTL
    usersdic[data['user_name']] = { hashedpwd, createdAt: Date.now() };

    // Save to MongoDB
    const customer = new Customers({
        "user_name": data['user_name'],
        "age": data['age'],
        "password": hashedpwd,
        "email": data['email']
    });
    await customer.save();

    res.status(201).send("Customer added successfully");
});

// Function to clean expired users from memory periodically
setInterval(() => {
    const now = Date.now();
    Object.keys(usersdic).forEach(user_name => {
        const user = usersdic[user_name];
        if (now - user.createdAt > usersTTL) {
            console.log(`Removing expired user: ${user_name}`);
            delete usersdic[user_name]; // Remove user from memory if expired
        }
    });
}, usersTTL); // Run every 15 minutes (or whatever TTL is set)

// GET endpoint for user logout
app.get('/api/logout', (req, res) => {
    res.cookie('token', '', { expires: new Date(0) }); // Clear the token from the client (cookie or storage)
    delete usersdic[username];  // Clear the user's data from in-memory cache
    res.redirect('/'); // Redirect user to the homepage or login page
    res.status(200).send('Logged out successfully');
});

// GET endpoint for the root URL, serving the home page
app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'home.html'));
});

// Starting the server and listening on the specified port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
