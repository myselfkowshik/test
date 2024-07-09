const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken'); // For JWT verification
const User = mongoose.model('User'); // Replace 'User' with your actual model name

// Middleware to verify JWT token (replace with your actual implementation)
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = decoded; // Attach decoded user data to the request object
    next();
  });
};

router.put('/users/:userId/password', verifyJWT, async (req, res) => {
  const userId = req.params.userId;
  const { currentPassword, newPassword } = req.body;

  // Check if user IDs match
  if (userId !== req.user._id.toString()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Find the user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect current password' });
    }

    // Hash the new password
    const saltRounds = 10; // Adjust salt rounds as needed
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user password
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;