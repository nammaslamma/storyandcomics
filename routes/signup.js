const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User'); // Assuming you have a User model in the models folder

// Sign-up Route
router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    // Validation - Ensure all fields are filled
    if (!username || !email || !password) {
        return res.render('signup', { error: 'Please fill in all fields.' });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render('signup', { error: 'Email is already registered. Please use a different email.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user in the database
        const newUser = new User({
            username: username,
            email: email,
            password: hashedPassword
        });

        // Save user to the database
        await newUser.save();

        // Send success flash message and redirect to login
        return res.render('signup', { success: 'Account created successfully. Please log in.' });

    } catch (error) {
        console.error('Error during signup:', error);
        return res.render('signup', { error: 'Something went wrong. Please try again.' });
    }
});

module.exports = router;
