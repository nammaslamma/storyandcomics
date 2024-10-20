const express = require('express');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const router = express.Router();

// Email setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Rate limiting
const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 signup requests per window
    message: 'Too many signup attempts from this IP, please try again after 15 minutes.'
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per window
    message: 'Too many login attempts from this IP, please try again after 15 minutes.'
});

// Middleware to redirect if user is authenticated
function redirectIfAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

// Sign-Up form (GET)
router.get('/signup', redirectIfAuthenticated, (req, res) => {
    res.render('signup', { error: req.flash('error'), success: req.flash('success') });
});

// Sign-Up Success (GET)
router.get('/signup-success', (req, res) => {
    res.render('signup-success');
});

// Sign-Up (POST) - Register a new user
router.post(
    '/signup', 
    signupLimiter,
    body('username').trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const errorMessages = errors.array().map(err => err.msg);
            req.flash('error', errorMessages.join(' '));
            return res.redirect('/auth/signup');
        }

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
                isVerified: false,
                verificationToken: crypto.randomBytes(32).toString('hex'),
                verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours expiry
            });

            // Save the new user
            await newUser.save();

            // Send verification email
            const verificationLink = `${process.env.APP_URL}/auth/verify-email?token=${newUser.verificationToken}&email=${email}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verify Your Email',
                text: `Hello ${username}, please verify your email by clicking this link: ${verificationLink}`
            };

            try {
                await transporter.sendMail(mailOptions);
            } catch (error) {
                console.error('Error sending email:', error);
                req.flash('error', 'There was an error sending the verification email. Please try again later.');
                return res.redirect('/auth/signup');
            }

            res.redirect('/auth/signup-success'); // Redirect to signup success page
        } catch (err) {
            console.error(err);
            req.flash('error', 'An error occurred during sign-up.');
            res.redirect('/auth/signup');
        }
    }
);

// Login form (GET)
router.get('/login', redirectIfAuthenticated, (req, res) => {
    res.render('login', { error: req.flash('error'), success: req.flash('success') });
});

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours

// Login (POST) - Handle user login
router.post('/login', loginLimiter, (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        if (err) return next(err);

        if (!user) {
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/auth/login');
        }

        // Check if the account is locked
        if (user.isLocked && user.lockUntil > Date.now()) {
            req.flash('error', 'Your account is locked. Please try again later.');
            return res.redirect('/auth/login');
        }

        // Check if the account is verified
        if (!user.isVerified) {
            req.flash('error', 'Your email is not verified. Please check your inbox.');
            return res.redirect('/auth/login');
        }

        // If login failed previously, increment login attempts
        if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
            user.isLocked = true;
            user.lockUntil = Date.now() + LOCK_TIME;
            await user.save();
            req.flash('error', 'Your account has been locked due to too many failed login attempts.');
            return res.redirect('/auth/login');
        }

        // Successful login
        req.logIn(user, async (err) => {
            if (err) return next(err);

            // Reset login attempts upon successful login
            user.loginAttempts = 0;
            await user.save();

            req.flash('success', 'You are now logged in.');
            res.redirect('/');
        });
    })(req, res, next);
});

// Forgot Password (GET)
router.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: req.flash('error'), success: req.flash('success') });
});

// Forgot Password (POST)
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            req.flash('error', 'No account found with that email.');
            return res.redirect('/auth/forgot-password');
        }

        // Generate reset token
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

// Reset Password (GET)
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

// Reset Password (POST)
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

        // Hash new password and update user
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

// Verify Email (GET)
router.get('/verify-email', async (req, res) => {
    const { token, email } = req.query;

    try {
        const user = await User.findOne({
            email,
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error', 'Invalid or expired verification token.');
            return res.redirect('/auth/login');
        }

        // Verify user
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
