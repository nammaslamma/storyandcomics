const express = require('express');
const router = express.Router();
const Story = require('../models/Story'); // Import the Story model

// GET route for story submission form
router.get('/submit', (req, res) => {
    res.render('submit-story'); // Render the form to submit a story
});

// POST route for submitting a story
router.post('/submit', async (req, res) => {
    try {
        // Example mock user if not logged in (replace this with real authentication later)
        if (!req.user) {
            req.user = { _id: '631f18b4f48d2c2bbf9c01a7', username: 'testuser' }; // Mocked user for testing
        }

        const { title, content } = req.body;

        const newStory = new Story({
            title,
            content,
            author: req.user._id // Link the story to the user
        });

        await newStory.save(); // Save the story to the database
        res.redirect('/story'); // Redirect to the list of stories
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
