const mongoose = require("mongoose");

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

module.exports = { ChatScheme };