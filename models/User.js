const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // For generating tokens

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false }, // To track email verification status
    verificationToken: { type: String }, // Token for email verification
    verificationTokenExpires: { type: Date }, // Expiration for email verification token
    resetPasswordToken: { type: String }, // Token for password reset
    resetPasswordExpires: { type: Date }, // Expiration for password reset token
    lastLoginIP: { type: String }, // Store the last IP the user logged in from
    failedAttempts: { type: Number, default: 0 }, // Track failed login attempts for security
    lockUntil: { type: Date } // Lock account for some time if too many failed attempts
});

// Encrypt the password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Method to compare passwords during login
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Method to generate email verification token
userSchema.methods.generateVerificationToken = function() {
    const token = crypto.randomBytes(20).toString('hex');
    this.verificationToken = token;
    this.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // Expires in 24 hours
    return token;
};

// Method to generate a password reset token
userSchema.methods.generatePasswordResetToken = function() {
    const token = crypto.randomBytes(20).toString('hex');
    this.resetPasswordToken = token;
    this.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // Expires in 1 hour
    return token;
};

// Check if the account is locked due to too many failed attempts
userSchema.methods.isAccountLocked = function() {
    return this.lockUntil && this.lockUntil > Date.now();
};

// Lock the account after too many failed attempts
userSchema.methods.incrementFailedAttempts = async function() {
    const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours lock time
    if (this.isAccountLocked()) {
        return;
    }

    this.failedAttempts += 1;
    if (this.failedAttempts >= 3) { // Lock after 3 failed attempts
        this.lockUntil = Date.now() + LOCK_TIME;
    }
    await this.save();
};

module.exports = mongoose.model('User', userSchema);
