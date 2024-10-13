const mongoose = require('mongoose');

const storySchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to the User model
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Story', storySchema);
