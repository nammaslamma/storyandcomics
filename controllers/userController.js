const User = require('../models/User');

// Function to handle user login
exports.loginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/auth/login');
        }

        // Check if account is locked
        if (user.isAccountLocked()) {
            req.flash('error', 'Your account is locked. Please try again later.');
            return res.redirect('/auth/login');
        }

        // Compare the password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            // Increment failed login attempts
            await user.incrementFailedAttempts();
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/auth/login');
        }

        // Reset failed login attempts on successful login
        user.failedAttempts = 0;
        user.lockUntil = undefined;
        await user.save();

        // Log the user in
        req.login(user, (err) => {
            if (err) {
                return next(err);
            }
            req.flash('success', 'You are now logged in!');
            res.redirect('/');
        });
    } catch (error) {
        next(error);
    }
};

// Function to handle user registration
exports.registerUser = async (req, res, next) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email is already registered.');
            return res.redirect('/auth/signup');
        }

        const newUser = new User({ username, email, password });
        await newUser.save();

        req.flash('success', 'Account created successfully. Please log in.');
        res.redirect('/auth/login');
    } catch (error) {
        next(error);
    }
};

// Function to handle account lock and failed attempts
exports.checkAccountLock = async (req, res, next) => {
    const user = req.user;
    if (user.isAccountLocked()) {
        req.flash('error', 'Your account is locked. Try again later.');
        return res.redirect('/auth/login');
    }
    next();
};
