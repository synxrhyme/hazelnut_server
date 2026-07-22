const { aesGcmEncrypt } = require("./CryptUtils");
const { safeLog } = require("./ServerControl");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
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
        safeLog("Successfully sent message:", response);
    } catch (error) {
        safeLog("Error sending message:", error);
    }
}

async function broadcast(wss, payload) {
    const receiversList = payload.body.receiversList;

    wss.clients.forEach(async (client) => {
        if (client.ready == true && receiversList.some(r => r.userId === client.userId)) {
            safeLog("broadcasting to:", client.userId);

            const _enc = await aesGcmEncrypt(client.sessionKey, JSON.stringify(payload));
            const response = JSON.stringify({ type: "enc", iv: _enc.iv, data: _enc.data, tag: _enc.tag });
            safeLog("response", response);
            
            client.send(response);
        }
    });
};

module.exports = {
    auth,
    isEmptyObject,
    sendPushNotification,
    broadcast
}