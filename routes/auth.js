const express = require('express');
const passport = require('passport');
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
            isVerified: false // User is unverified initially
        });

        // Generate email verification token and expiry (24 hours)
        newUser.verificationToken = crypto.randomBytes(32).toString('hex');
        newUser.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours expiry

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

        await transporter.sendMail(mailOptions);

        res.redirect('/auth/signup-success'); // Redirect to signup success page

    } catch (err) {
        console.error(err);
        req.flash('error', 'An error occurred during sign-up.');
        res.redirect('/auth/signup');
    }
});

// Login form (GET)
router.get('/login', (req, res) => {
    res.render('login', { error: req.flash('error'), success: req.flash('success') });
});

// Login (POST) - Handle user login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/auth/login');
        }
        if (user.isLocked) {
            req.flash('error', 'Your account is locked. Please contact support.');
            return res.redirect('/auth/login');
        }
        if (!user.isVerified) {
            req.flash('error', 'Your email is not verified. Please check your inbox.');
            return res.redirect('/auth/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            req.flash('success', 'You are now logged in!');
            return res.redirect('/'); // Redirect to home page upon successful login
        });
    })(req, res, next);
});

// Forgot Password (GET) - Render forgot password form
router.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: req.flash('error'), success: req.flash('success') });
});

// Forgot Password (POST) - Send reset password link
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            req.flash('error', 'No account found with that email.');
            return res.redirect('/auth/forgot-password');
        }

        // Generate password reset token and expiry (1 hour)
        user.resetPasswordToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        // Send reset password email
        const resetLink = `${process.env.APP_URL}/auth/reset-password?token=${user.resetPasswordToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset',
            text: `Hello, you requested a password reset. Click this link to reset your password: ${resetLink}`
        };

        await transporter.sendMail(mailOptions);

        req.flash('success', 'Password reset email sent. Please check your inbox.');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error', 'An error occurred while trying to send the password reset email.');
        res.redirect('/auth/forgot-password');
    }
});

// Reset Password (GET) - Render reset password form
router.get('/reset-password', async (req, res) => {
    const { token } = req.query;
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Invalid or expired token.');
            return res.redirect('/auth/forgot-password');
        }

        res.render('reset-password', { token, error: req.flash('error'), success: req.flash('success') });
    } catch (err) {
        console.error(err);
        req.flash('error', 'An error occurred.');
        res.redirect('/auth/forgot-password');
    }
});

// Reset Password (POST) - Update the password
router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Invalid or expired token.');
            return res.redirect('/auth/forgot-password');
        }

        // Hash new password and update the user record
        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        req.flash('success', 'Password successfully reset. You can now log in.');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error', 'An error occurred while resetting your password.');
        res.redirect('/auth/forgot-password');
    }
});

// Verify Email (GET) - Handles email verification link
router.get('/verify-email', async (req, res) => {
    const { token, email } = req.query;

    try {
        const user = await User.findOne({
            email,
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() } // Token is not expired
        });

        if (!user) {
            req.flash('error', 'Invalid or expired verification token.');
            return res.redirect('/auth/login');
        }

        // Verify the user
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        req.flash('success', 'Your email has been verified.');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error', 'An error occurred while verifying your email.');
        res.redirect('/auth/login');
    }
});

module.exports = router;
