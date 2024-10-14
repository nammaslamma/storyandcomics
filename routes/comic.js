const express = require('express');
const router = express.Router();
const multer = require('multer');
const Comic = require('../models/Comic'); // Assuming you have a Comic model

// Multer setup for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/comics'); // Save uploads in this folder
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Unique filename
    }
});

const upload = multer({ storage: storage });

// GET route for comic submission form
router.get('/submit', (req, res) => {
    if (!req.user) {
        return res.redirect('/auth/login'); // Ensure user is logged in
    }
    res.render('comic-submit'); // Render the form to submit a comic
});

// POST route for submitting a comic (supports multiple image uploads)
router.post('/submit', upload.array('comicPages', 10), async (req, res) => {
    try {
        if (!req.user) {
            return res.redirect('/auth/login'); // Ensure user is logged in
        }

        const { title } = req.body;
        const comicPages = req.files.map(file => file.path); // Store file paths of uploaded images

        const newComic = new Comic({
            title,
            comicFiles: comicPages,  // Array of uploaded comic pages
            author: req.user._id // Link the comic to the user
        });

        await newComic.save(); // Save the comic to the database
        res.redirect(`/profile/${req.user._id}`); // Redirect to user's profile after submission
    } catch (err) {
        console.error(err);
        res.status(500).send("Error submitting the comic");
    }
});

// GET route to view a comic
router.get('/view/:id', async (req, res) => {
    try {
        const comic = await Comic.findById(req.params.id).populate('author'); // Get comic and populate author
        res.render('comic-view', { comic });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading comic");
    }
});

// GET route for searching comics
router.get('/search', async (req, res) => {
    const query = req.query.q;
    try {
        const comics = await Comic.find({
            title: new RegExp(query, 'i') // Search by title (case-insensitive)
        }).sort({ createdAt: -1 }); // Sort by most recent first
        res.render('comics', { comics });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error searching comics");
    }
});

// GET route to display all comics
router.get('/', async (req, res) => {
    try {
        const comics = await Comic.find().sort({ createdAt: -1 });
        res.render('comics', { comics });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error retrieving comics");
    }
});

module.exports = router;
