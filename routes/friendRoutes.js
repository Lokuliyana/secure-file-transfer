const express = require('express');
const User = require('../models/User');
const verifyToken = require('../middleware/verifyToken');
const Notification = require('../models/Notifications'); // Assuming this is the correct path

const router = express.Router();
const mongoose = require("mongoose");

router.post('/friend-request/:userId', verifyToken, async (req, res) => {
    try {
      const recipient = await User.findById(req.params.userId);
      if (!recipient) return res.status(404).send('User not found.');
  
      if (recipient.friendRequests.some(request => request.userId.equals(req.user._id))) {
        return res.status(400).send('Friend request already sent.');
      }
  
      recipient.friendRequests.push({ userId: req.user._id });
      await recipient.save();
      
      console.log("🔐 Sender (req.user):", req.user);
      const sender = await User.findById(req.user._id);
      console.log("👤 Sender full object:", sender);
  
      const newNotification = new Notification({
        userId: req.params.userId, // recipient
        type: 'Friend Request',
        title: 'New Friend Request',
        message: `${sender.username} has sent you a friend request.`, // ✅
      });
  
      await newNotification.save();
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

        const newNotification = new Notification({
            userId: requesterId, // Requester's ID
            type: 'Accept Friend Request',
            title: 'Friend Request Accepted',
            message: `${currentUser.username} has accepted your friend request.`,
        });
        await newNotification.save();

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

// Remove a friend (bi-directionally)
router.delete('/remove-friend/:userId', verifyToken, async (req, res) => {
    try {
        const userIdToRemove = req.params.userId;
        const currentUserId = req.user._id;

        // Fetch both users
        const currentUser = await User.findById(currentUserId);
        const friend = await User.findById(userIdToRemove);

        if (!currentUser || !friend) {
            return res.status(404).json({ message: "User not found." });
        }

        // Remove each other from their friends array
        currentUser.friends = currentUser.friends.filter(id => id.toString() !== userIdToRemove);
        friend.friends = friend.friends.filter(id => id.toString() !== currentUserId);

        // Save both users
        await currentUser.save();
        await friend.save();

        res.send('Friend removed.');
    } catch (error) {
        console.error("❌ Backend Remove Friend Error:", error); // 🐛 Debug log
        res.status(500).json({ message: "Error removing friend", error });
    }
});


// Toggle close friend status (Add or Remove)
router.post('/add-close-friend/:userId', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user.friends.includes(req.params.userId)) {
            return res.status(400).send('User is not a friend.');
        }

        const userId = req.params.userId;
        const isCloseFriend = user.closeFriends.includes(userId);

        if (isCloseFriend) {
            // Remove from close friends
            user.closeFriends = user.closeFriends.filter(id => id.toString() !== userId);
            await user.save();
            return res.send({ message: 'Removed from close friends.', closeFriends: user.closeFriends });
        } else {
            // Add to close friends
            user.closeFriends.push(userId);
            await user.save();
            return res.send({ message: 'Added to close friends.', closeFriends: user.closeFriends });
        }
    } catch (error) {
        res.status(500).json({ message: "Error updating close friend status", error });
    }
});

// Get Friend's Profile
router.get('/profile/:userId', verifyToken, async (req, res) => {
    try {
      const friend = await User.findById(req.params.userId).select('-password -otp -otpExpiry');
      if (!friend) {
        return res.status(404).json({ message: "User not found" });
      }
  
      const currentUserId = new mongoose.Types.ObjectId(req.user._id);
  
      const isFriend = friend.friends.includes(currentUserId);
      const isCloseFriend = friend.closeFriends.includes(currentUserId);
  
      // ✅ Check if the current user has already sent a friend request to the target friend
      const youRequested = friend.friendRequests.some(req => req.userId.equals(currentUserId));
  
      // ✅ Check if the target friend has already sent a request to the current user
      const currentUser = await User.findById(currentUserId);
      const hasRequestedYou = currentUser.friendRequests.some(req => req.userId.equals(friend._id));
  
      // 🔒 If private and not a friend
      const isPrivate = friend.privacySetting === "private";
      if (isPrivate && !isFriend) {
        return res.json({
          _id: friend._id,
          username: friend.username,
          email: friend.email,
          avatar: friend.avatar || 'default-avatar.png',
          isPrivate: true,
          isFriend: false,
          hasRequestedYou,
          youRequested,
          files: []
        });
      }
  
      res.json({
        _id: friend._id,
        username: friend.username,
        email: friend.email,
        avatar: friend.avatar || 'default-avatar.png',
        isPrivate: friend.isPrivate || false,
        isFriend,
        isCloseFriend,
        hasRequestedYou,
        youRequested,
        files: friend.files || []
      });
  
    } catch (error) {
      console.error("🔥 Profile Fetch Error:", error);
      res.status(500).json({ message: "Error fetching profile", error });
    }
  });


module.exports = router;
