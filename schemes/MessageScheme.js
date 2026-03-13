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

module.exports = { MessageScheme };