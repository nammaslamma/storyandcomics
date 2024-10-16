const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Story = require('../models/Story');

// GET route to display a user's profile
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const stories = await Story.find({ author: user._id }).sort({ createdAt: -1 }); // Get user's stories, most recent first
        const isOwner = req.user && req.user._id.toString() === user._id.toString(); // Check if the logged-in user is the profile owner

        res.render('profile', { user, stories, isOwner }); // Render profile page with 'isOwner' flag
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading profile");
    }
});

module.exports = router;
