const express = require('express');
const router = express.Router();
const Story = require('../models/Story'); // Import the Story model

// GET route for story submission form
router.get('/submit', (req, res) => {
    if (!req.user) {
        return res.redirect('/auth/login'); // Ensure user is logged in
    }
    res.render('story-submit'); // Render the form to submit a story
});

// POST route for submitting a story
router.post('/submit', async (req, res) => {
    try {
        if (!req.user) {
            return res.redirect('/auth/login'); // Ensure user is logged in
        }

        const { title, content } = req.body;

        const newStory = new Story({
            title,
            content,
            author: req.user._id // Link the story to the user
        });

        await newStory.save(); // Save the story to the database
        res.redirect(`/profile/${req.user._id}`); // Redirect to the user's profile after submission
    } catch (err) {
        console.error(err);
        res.status(500).send("Error submitting the story");
    }
});

// GET route for searching stories
router.get('/search', async (req, res) => {
    const query = req.query.q;
    try {
        const stories = await Story.find({
            title: new RegExp(query, 'i') // Search by title (case-insensitive)
        }).sort({ createdAt: -1 }); // Sort by most recent first
        res.render('stories', { stories });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error searching stories");
    }
});

// GET route to display a specific story
router.get('/view/:id', async (req, res) => {
    try {
        const story = await Story.findById(req.params.id).populate('author'); // Fetch story and populate author details
        res.render('story-view', { story });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading story");
    }
});

// GET route to display all stories
router.get('/', async (req, res) => {
    try {
        const stories = await Story.find().sort({ createdAt: -1 }); // Most recent first
        res.render('stories', { stories });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error retrieving stories");
    }
});

module.exports = router;
