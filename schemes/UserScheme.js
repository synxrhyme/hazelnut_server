const mongoose = require("mongoose");

const UserScheme = new mongoose.Schema({
    userId:           String,
    username:         String,
    fcmToken:         String,
    refreshToken:     String,
    createdTimestamp: String,

    online:           { type: Boolean, default: false },
    lastSeen:         { type: String,  default: () => new Date().toISOString() },
});

module.exports = { UserSchemes };