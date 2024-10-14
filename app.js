// 1. Import necessary modules
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const flash = require('connect-flash');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const path = require('path');
const User = require('./models/User');
const Story = require('./models/Story');
require('dotenv').config();

const app = express();

// 2. Use Helmet for security
app.use(helmet());

// 3. Email setup using nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 4. Middleware to handle form data and public files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// 5. Set EJS as the view engine
app.set('view engine', 'ejs');

// 6. Express session with MongoStore (using MongoDB for session storage)
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URL,
        collectionName: 'sessions',
        ttl: 60 * 60 * 24
    }),
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// 7. Passport.js middleware for authentication
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// 8. Pass flash messages and user data to all templates
app.use((req, res, next) => {
    res.locals.error = req.flash('error');
    res.locals.user = req.user || null; // Pass the logged-in user data to templates
    next();
});

// 9. Passport Local Strategy for authentication
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'Incorrect email.' });
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Serialize user into session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// 10. Protect routes that require authentication
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/auth/login');
}

// 11. Routes
const storyRoutes = require('./routes/story');
const profileRoutes = require('./routes/profile');
const authRoutes = require('./routes/auth');

app.use('/story', ensureAuthenticated, storyRoutes);
app.use('/profile', profileRoutes);
app.use('/auth', authRoutes);

// Homepage Route
app.get('/', async (req, res) => {
    try {
        const stories = await Story.find().populate('author').sort({ createdAt: -1 });
        res.render('home', { stories, user: req.user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error loading homepage');
    }
});

// MongoDB connection using the Railway MongoDB URL
mongoose.connect(process.env.MONGO_URL, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.log("MongoDB connection error:", err));

// 12. Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
