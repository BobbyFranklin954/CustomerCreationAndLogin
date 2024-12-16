// Load environment variables
require('dotenv').config();
const path = require('path');

// Get the mode from an environment variable
const mode = process.env.APP_MODE || 'stateful-session'; // Default to 'stateful-session' | 'stateless-jwt'

// Dynamically require the correct version of customer_app.js
let customerApp;
try {
    customerApp = require(path.join(__dirname, mode, 'customer_app.js'));
    console.log(`Loaded ${mode} version of customer_app.js`);
} catch (err) {
    console.error(`Error loading ${mode} version:`, err.message);
    process.exit(1);
}

// Call a function or export the module to start your app
if (customerApp.start) {
    customerApp.start();
} else {
    console.error("Customer app did not export a start function.");
}