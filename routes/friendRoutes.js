const express = require('express');
const User = require('../models/User');
const verifyToken = require('../middleware/verifyToken');

const router = express.Router();

// Send a friend request
router.post('/friend-request/:userId', verifyToken, async (req, res) => {
    try {
        const recipient = await User.findById(req.params.userId);
        if (!recipient) return res.status(404).send('User not found.');

        if (recipient.friendRequests.some(request => request.userId.equals(req.user._id))) {
            return res.status(400).send('Friend request already sent.');
        }

        recipient.friendRequests.push({ userId: req.user._id });
        await recipient.save();

        res.send('Friend request sent.');
    } catch (error) {
        res.status(500).json({ message: "Error sending friend request", error });
    }
});

// Accept a friend request
router.post('/accept-friend-request/:userId', verifyToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user._id);
        const requesterId = req.params.userId;

        // Remove the friend request
        currentUser.friendRequests = currentUser.friendRequests.filter(request => !request.userId.equals(requesterId));
        
        // Add to friends list
        currentUser.friends.push(requesterId);
        await currentUser.save();

        // Also update the requester's friend list
        const requester = await User.findById(requesterId);
        requester.friends.push(req.user._id);
        await requester.save();

        res.send('Friend request accepted.');
    } catch (error) {
        res.status(500).json({ message: "Error accepting friend request", error });
    }
});

// Reject a friend request
router.post('/reject-friend-request/:userId', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        user.friendRequests = user.friendRequests.filter(request => !request.userId.equals(req.params.userId));
        await user.save();

        res.send('Friend request rejected.');
    } catch (error) {
        res.status(500).json({ message: "Error rejecting friend request", error });
    }
});

// Search for users by name, username, or email
router.get('/search', verifyToken, async (req, res) => {
    const { search } = req.query;
    if (!search) {
        return res.status(400).send('Search query is required.');
    }

    try {
        const users = await User.find({
            $or: [
                { name: { $regex: search, $options: 'i' } },
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ]
        }).select('-password -otp -otpExpiry'); // Exclude sensitive information

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users", error });
    }
});

// View the user's friends list
router.get('/friends', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('friends', 'username email');
        res.json(user.friends);
    } catch (error) {
        res.status(500).json({ message: "Error fetching friends list", error });
    }
});

// Remove a friend
router.delete('/remove-friend/:userId', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        user.friends = user.friends.filter(friendId => !friendId.equals(req.params.userId));
        await user.save();

        res.send('Friend removed.');
    } catch (error) {
        res.status(500).json({ message: "Error removing friend", error });
    }
});

// Add a close friend
router.post('/add-close-friend/:userId', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user.friends.includes(req.params.userId)) {
            return res.status(400).send('User is not a friend.');
        }
        if (user.closeFriends.includes(req.params.userId)) {
            return res.status(400).send('Already a close friend.');
        }

        user.closeFriends.push(req.params.userId);
        await user.save();

        res.send('Added to close friends.');
    } catch (error) {
        res.status(500).json({ message: "Error adding close friend", error });
    }
});



module.exports = router;
