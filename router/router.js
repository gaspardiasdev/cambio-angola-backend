// router.js
const express = require('express');
const router = express.Router();

// Add your routes here
router.get('/', (req, res) => {
    res.json({ message: 'API is working' });
});

module.exports = router;