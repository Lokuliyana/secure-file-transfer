const express = require('express');
const User = require('../models/User');
const verifyToken = require('../middleware/verifyToken');
const Notification = require('../models/Notifications'); // Assuming this is the correct path

const router = express.Router();
const mongoose = require("mongoose");

router.post('/friend-request/:userId', verifyToken, async (req, res) => {
    try {
      const recipient = await User.findById(req.params.userId);
      const sender = await User.findById(req.user._id);
    
      if (!recipient || !sender) return res.status(404).send("User not found.");
  
      // Can't send request to self
      if (recipient._id.equals(sender._id)) {
        return res.status(400).send("Cannot send friend request to yourself.");
      }
  
      // Already friends
      if (recipient.friends.includes(sender._id)) {
        return res.status(400).send("Already friends.");
      }
  
      // Already sent (check if sender already in recipient's requests)
      const alreadyRequested = recipient.friendRequests.some(req =>
        req.userId.equals(sender._id)
      );
      if (alreadyRequested) {
        return res.status(400).send("Friend request already sent.");
      }
  
      // Check recipient's privacy setting
      if (recipient.privacySetting === "public") {
        // Auto accept friend request (mutual add)
        recipient.friends.push(sender._id);
        sender.friends.push(recipient._id);
        await recipient.save();
        await sender.save();
  
        const autoNotification = new Notification({
          userId: recipient._id,
          type: "Friend Request",
          title: "New Friend Added",
          message: `${sender.username} has added you as a friend.`,
        });
        await autoNotification.save();
  
        return res.send("Friend added automatically (public profile).");
      } else {
        // Private: store in recipient's friendRequests
        recipient.friendRequests.push({
          userId: sender._id,
          createdAt: new Date(),
        });
        await recipient.save();
  
        const reqNotification = new Notification({
          userId: recipient._id,
          type: "Friend Request",
          title: "New Friend Request",
          message: `${sender.username} sent you a friend request.`,
        });
        await reqNotification.save();
  
        return res.send("Friend request sent (private profile).");
      }
    } catch (error) {
      console.error("Friend request error:", error);
      res.status(500).json({ message: "Error processing friend request", error });
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


// Cancel a sent friend request
router.post('/cancel-friend-request/:userId', verifyToken, async (req, res) => {
    try {
      const recipient = await User.findById(req.params.userId);
      if (!recipient) return res.status(404).send("Recipient not found.");
  
      // Remove sender's ID from recipient's friendRequests
      recipient.friendRequests = recipient.friendRequests.filter(request =>
        !request.userId.equals(req.user._id)
      );
  
      await recipient.save();
      res.send("Friend request cancelled.");
    } catch (error) {
      console.error("❌ Cancel request error:", error);
      res.status(500).json({ message: "Error cancelling friend request", error });
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

router.get('/friends', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('friends', 'username email profilePicture');
        const response = user.friends.map(friend => {
            const fullProfileUrl = friend.profilePicture?.startsWith('/uploads')
              ? `http://localhost:3000${friend.profilePicture}`
              : "default-profile.jpg";
          
            return {
              _id: friend._id,
              username: friend.username,
              email: friend.email,
              profilePicture: fullProfileUrl,
              isCloseFriend: user.closeFriends.includes(friend._id.toString()),
            };
          });          
      
      res.json(response);
    } catch (error) {
      console.error("Error fetching friends list:", error);
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

// ✅ Save full updated close friend list
router.post('/save-close-friends', verifyToken, async (req, res) => {
    try {
      const { closeFriends } = req.body; // [array of userIds]
      const user = await User.findById(req.user._id);
  
      // Validate all are actual friends
      const invalidIds = closeFriends.filter(id => !user.friends.includes(id));
      if (invalidIds.length > 0) {
        return res.status(400).json({ message: "Some users are not your friends." });
      }
  
      // ✅ Update without triggering version conflict
      const updated = await User.findByIdAndUpdate(
        req.user._id,
        { closeFriends },
        { new: true, useFindAndModify: false }
      );
  
      return res.json({ message: "✅ Close friends updated.", closeFriends: updated.closeFriends });
  
    } catch (err) {
      console.error("Save close friends error:", err);
      return res.status(500).json({ message: "Server error", error: err.toString() });
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

      const isSelf = friend._id.equals(currentUserId);
  
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
          profilePicture: friend.profilePicture || 'default-avatar.png',
          isPrivate: true,
          isFriend: false,
          isSelf,
          hasRequestedYou,
          youRequested,
          files: []
        });
      }
  
      res.json({
        _id: friend._id,
        username: friend.username,
        email: friend.email,
        profilePicture: friend.profilePicture || 'default-avatar.png',
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
