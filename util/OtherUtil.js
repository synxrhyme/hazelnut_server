const jwt = require("jsonwebtoken");
const JWT_SECRET_KEY = process.env.JWT_SECRET;

async function auth(userModel, userId, token) {
    try {
        const payload = jwt.verify(token, JWT_SECRET_KEY);
        if (payload.userId !== userId) return 1; // -- Token passt nicht zu UserID

        const user = await userModel.findOne({ userId: userId });
        if (user == null) return 2; // -- User nicht gefunden

        if (user.userId == userId) return 0; // -- Erfolgreich authentifiziert
    }

    catch (err) {
        if (err.name === "TokenExpiredError") return 3;
        throw new Error(err); // -- Invalider Token
    }
    
}

function isEmptyObject(obj) {
    for (var key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            return false;
        }
    }
    return true;
}

async function sendPushNotification(fcmToken, chat, sentTimestamp) {
    const message = {
        token: fcmToken,
        data: {
            type: "new_message",
            chatName: chat.chatName.toString(),
            chatId: chat.chatId.toString(),
            sentTimestamp: sentTimestamp,
        },
        android: {
            priority: "HIGH",
        },
        apns: {
            headers: {
                "apns-priority": "10"
            },
            payload: {
                aps: {
                    sound: "default"
                }
            }
        }
    };

    try {
        const response = await admin.messaging().send(message);
        console.log("Successfully sent message:", response);
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

module.exports = {
    auth,
    isEmptyObject,
    sendPushNotification
}