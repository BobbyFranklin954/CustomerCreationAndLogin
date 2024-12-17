// Importing necessary libraries and modules
require('dotenv').config();
const path = require('path');
const mongoose = require('mongoose');            // MongoDB ODM library
const Customers = require(path.join(__dirname, '..', 'customer'));         // Imported MongoDB model for 'customers'
const express = require('express');              // Express.js web framework
const session = require('express-session');
const bodyParser = require('body-parser');       // Middleware for parsing JSON requests
const bcrypt = require("bcryptjs")
const saltRounds = 5
const winston = require('winston');
const { ValidationError, InvalidUserError, AuthenticationFailed } = require(path.join(__dirname, '..', '/errors/CustomError'));

const app = express();
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

const uri = `mongodb://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_URI}?authSource=admin`;
mongoose.connect(uri, { 'dbName': 'customerDB' });

// Middleware to parse JSON requests
app.use("*", bodyParser.json());

// Serving static files from the 'frontend' directory under the '/static' route
app.use('/static', express.static(path.join(".", 'frontend')));

// Middleware to handle URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));

app.use((err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "Error";
    console.log(err.stack);
    res.status(err.statusCode).json({
        status: err.statusCode,
        message: err.message,
    });
})

const uuid = require('uuid'); //Generate a unique session id
const { debug } = require('console');

app.use(session({
    cookie: { maxAge: 120000 }, // Session expires after 2 minutes of inactivity
    secret: process.env.SESSION_SECRET,
    res: false,
    saveUninitialized: true,
    genid: () => uuid.v4()
}));

let usersdic = {}; // In memory store for username and password

// POST endpoint for user login
app.post('/api/login', async (req, res, next) => {
    const data = req.body;
    let user_name = data['user_name'];
    let password = data['password'];

    try {
        debugger;// If not in memory, check MongoDB
        const user = await Customers.findOne({ user_name: data['user_name'] });
        if (!user) {
            throw new InvalidUserError("No such user in database");
        }
        const isMatch = await bcrypt.compare(password, user.password); // Compare the provided password with the hashed password in the database
        if (!isMatch) {
            throw new AuthenticationFailed("Password Incorrect! Try again");
        } else {
            const genidValue = req.sessionID; // Assuming session middleware is active
            res.cookie('username', user_name);
            logger.info(`User ${user_name} logged in successfully with session ID: ${genidValue}`); // Log successful login
            res.status(200).redirect('/static/home.html'); // Redirect to the home page
        }
    } catch (error) {
        next(error);
    }
});

// POST endpoint for adding a new customer
app.post('/api/add_customer', async (req, res, next) => {
    const data = req.body;
    const age = parseInt(data['age']);
    let cust_fname = data['cust_fname'];
    let cust_lname = data['cust_lname'];

    try {
        if (age < 21) {
            throw new ValidationError("Customer Under required age limit");
        }
        // Validate that first and last names are strings containing only letters
        const nameRegex = /^[a-zA-Z\s-]+$/; // Regex to match only alphabetic characters
        if (!nameRegex.test(cust_fname) || !nameRegex.test(cust_lname)) {
            throw new ValidationError("Names must contain letters only");
        }

        const documents = await Customers.find({ user_name: data['user_name'] });
        if (documents.length > 0) {
            return res.send("User already exists");
        }

        let hashedpwd = bcrypt.hashSync(data['password'], saltRounds)

        // Creating a new instance of the Customers model with data from the request
        const customer = new Customers({
            "user_name": data['user_name'],
            "name": data['name'],
            "cust_fname": data['cust_fname'],
            "cust_lname": data['cust_lname'],
            "age": data['age'],
            "password": hashedpwd,
            "email": data['email']
        });
        await customer.save(); // Saving the new customer to the MongoDB 'customers' collection

        res.send("Customer added successfully")
    } catch (error) {
        next(error);
    }
});

// GET endpoint for user logout
app.get('/api/logout', async (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return next(err);
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