const mongoose = require("mongoose");

const MessageScheme = new mongoose.Schema({
    messageId:         Number,
    chatId:            Number,
    senderId:          String,
    senderName:        String,
    text:              String,
    sentTimestamp:     String,

    receivers: [
      {
        userId: String,
        received: { type: Boolean, default: false },
        receivedTimestamp: { type: String, default: null },
      },
    ],
});

const ChatScheme = new mongoose.Schema({
    chatId:      Number,
    chatName:    String,
    chatAuth:    String,
    users:        [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }],
    createdById:      String,
    createdByName:    String,
    createdTimestamp: String,
});

const UserScheme = new mongoose.Schema({
    userId:           String,
    username:         String,
    fcmToken:         String,
    refreshToken:     String,
    createdTimestamp: String,

    online:           { type: Boolean, default: false },
    lastSeen:         { type: String,  default: () => new Date().toISOString() },
});

module.exports = { MessageScheme, ChatScheme, UserScheme };