const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const router = express.Router();
require('dotenv').config();

// Email setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Sign-Up form (GET)
router.get('/signup', (req, res) => {
    res.render('signup', { error: req.flash('error'), success: req.flash('success') });
});

// Sign-Up Success (GET)
router.get('/signup-success', (req, res) => {
    res.render('signup-success');
});

// Sign-Up (POST) - Register a new user
router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email is already registered.');
            return res.redirect('/auth/signup');
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            isVerified: false, // User is unverified initially
            verificationToken: crypto.randomBytes(32).toString('hex'),
            verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours expiry
        });

        // Save the new user
        await newUser.save();

        // Send verification email (using environment-based app URL)
        const verificationLink = `${process.env.APP_URL}/auth/verify-email?token=${newUser.verificationToken}&email=${email}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Email',
            text: `Hello ${username}, please verify your email by clicking this link: ${verificationLink}`
        };

        try {
            await transporter.sendMail(mailOptions);
            // If email is sent successfully, redirect to signup-success
            return res.redirect('/auth/signup-success');
        } catch (emailError) {
            console.error('Error sending email:', emailError);
            req.flash('error', 'An error occurred while sending verification email. Please try again.');
            return res.redirect('/auth/signup');
        }

    } catch (err) {
        console.error('Error during sign-up process:', err);
        req.flash('error', 'An unexpected error occurred during sign-up. Please try again.');
        return res.redirect('/auth/signup');
    }
});

module.exports = router;
