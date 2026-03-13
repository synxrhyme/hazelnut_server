const { MessageScheme } = require("../schemes/MessageScheme");
const { ChatScheme }    = require("../schemes/ChatScheme");
const { UserScheme }    = require("../schemes/UserScheme");

const dbConnection = mongoose.createConnection("mongodb://server:supersecuremongodbpassword@127.0.0.1:27017/hazelnut_db?authSource=admin");

const Message = dbConnection.model("Message", MessageScheme, "hazelnut_msgdb");
const Chat    = dbConnection.model("Chat", ChatScheme, "hazelnut_chatdb");
const User    = dbConnection.model("User", UserScheme, "hazelnut_userdb");

const { aesGcmDecrypt, aesGcmEncrypt } = require("../util/CryptUtils");
const { generateUserID, generateAuthToken, generateRefreshToken } = require("../util/TokenGeneration");

class EncryptedMessageHandler {
    constructor(client, data, secretKey) {
        this.client = client;
        this.raw = data;
        this.SECRET_KEY = secretKey;
    }

    async handleEncrypted() {
        if (!this.client.sessionKey) return;
        let replyPayload = {};

        try {
            const plaintext = aesGcmDecrypt(this.client.sessionKey, this.raw.iv, this.raw.data, this.raw.tag);
            console.log("Client → (dec):", plaintext);

            const data = JSON.parse(plaintext);

            const echoPayload = {
                type: "echo",
                timestamp: Date.now(),
                got: data,
            };

            const echoEnc = aesGcmEncrypt(this.client.sessionKey, JSON.stringify(echoPayload));
            this.client.send(JSON.stringify({ type: "enc", iv: echoEnc.iv, data: echoEnc.data, tag: echoEnc.tag }));

            switch (data.header) {
                case "auth": {
                    try {
                        const payload = jwt.verify(data.body.token, this.SECRET_KEY);
                        const userId = data.body.userId;
                        
                        if (payload.userId !== userId) {
                            console.log("Token passt nicht zu UserID.");
                        
                            replyPayload = {
                                header: "auth_response",
                                status: "token_invalid",
                                body: {
                                    timestamp: Date.now()
                                },
                            };
                        
                            break;
                        }
                    
                        else if (payload.userId === userId) {
                            const user = await User.findOne({ userId });
                        
                            if (user == null) {
                                console.log("User nicht gefunden.");
                            
                                replyPayload = {
                                    header: "auth_response",
                                    status: "user_invalid",
                                    body: {
                                        timestamp: Date.now()
                                    },
                                };
                            
                                break;
                            }
                        
                            else if (user.userId === userId) {
                                replyPayload = {
                                    header: "auth_response",
                                    status: "valid",
                                    body: {
                                        timestamp: Date.now()
                                    }
                                };

                                this.client.userId = userId;
                                this.client.ready = true;

                                await User.updateOne(
                                  { userId: userId },
                                  { $set: { online: true } }
                                );

                                break;
                            }
                        }   
                    }

                    catch (err) {
                        if (err.name === "TokenExpiredError") {
                            console.error("Error: Token abgelaufen.");
                        }
                        
                        else if (err.name === "JsonWebTokenError") {
                            console.error("Error: Token ungültig.");
                        }
                        
                        else {
                          console.error("Error: ", err);
                        }

                        replyPayload = {
                            header: "auth_response",
                            status: "token_invalid",
                            body: {
                                timestamp: Date.now()
                            },
                        };
                    }

                    break;
                }

                case "registration": {
                    console.log("New User");

                    const findUsername = await User.findOne({ username: data.body.username });
                    
                    if (findUsername !== null) {
                        replyPayload = {
                            header: "registration_response",
                            status: "username_taken",
                        }
                        
                        break;
                    }
                    
                    const findFcmToken = await User.findOne({ fcmToken: data.body.fcmToken });

                    if (findFcmToken !== null) {
                        replyPayload = {
                            header: "registration_response",
                            status: "app_already_registered",
                        }
                        
                        break;
                    }
                    
                    const now = new Date().toISOString();
                    const userId = generateUserID(data.body.fcmToken);

                    await User.create({
                        userId:           userId,
                        username:         data.body.username,
                        fcmToken:         data.body.fcmToken,
                        refreshToken:     generateRefreshToken(),
                        createdTimestamp: now,
                    });

                    const createdUser = await User.findOne({ userId });
                    console.log("Created user: " + createdUser);

                    replyPayload = {
                        header: "registration_response",
                        status: "success",
                        body: {
                            userId:            createdUser.userId,
                            username:          createdUser.username,
                            fcmToken:          createdUser.fcmToken,
                            authToken:         generateAuthToken(createdUser.userId, this.SECRET_KEY),
                            refreshToken:      createdUser.refreshToken,
                            createdTimestamp:  createdUser.createdTimestamp,
                        }
                    }

                    break;
                }

                case "refresh": {
                    // -- REFRESH TOKEN KÖNNTE GEKLAUT SEIN - TODO

                    const userId = data.userId;
                    const user = await User.findOne({ userId });

                    const now = new Date().toISOString();

                    if (user == null) {
                        replyPayload = {
                            header: "refresh_response",
                            status: "user_invalid",
                            body: {
                                timestamp: now,
                            }
                        };

                        break;
                    }

                    else if (user.userId === userId) {
                        const newAuthToken = generateAuthToken(userId, this.SECRET_KEY);

                        replyPayload = {
                            header: "refresh_response",
                            status: "valid",
                            body: {
                                authToken: newAuthToken,
                                timestamp: now
                            }
                        };

                        break;
                    }

                    break;
                }

                case "image_upload": {
                    console.log("Profile picture upload");
                    const buffer = Buffer.from(data.data, "base64");

                    fs.writeFileSync(
                        path.join(__dirname, "public", "images", data.user + ".png"),
                        buffer
                    );

                    console.log(
                        "Image saved as: " +
                            data.user +
                            ".png  --  at: " +
                            path.join(__dirname, "public", "images", data.user + ".png")
                    );

                    break;
                }

                case "create_chat": {
                    console.log("authCode:", data.authToken);
                    const authCode = await auth(data.userId, data.authToken);

                    switch (authCode) {
                        case 1: {
                            replyPayload = {
                                header: "chat_creation_response",
                                statusCode: 2, // -- Token passt nicht zu UserID
                            };

                            break;
                        }

                        case 2: {
                            replyPayload = {
                                header: "chat_creation_response",
                                statusCode: 3, // -- User nicht gefunden
                            };

                            break;
                        }
                        
                        case 0: break;
                    }

                    console.log("User creates new chatroom");

                    const now = new Date().toISOString();
                    const user = await User.findOne({ userId: data.userId });

                    if (!user) {
                        console.warn("invalid user");
                        return;
                    }

                    if (await Chat.findOne({ chatName: data.body.chatName }) != null) {
                        replyPayload = {
                            header: "chat_creation_response",
                            statusCode: 0, // -- Chat existiert schon
                        };

                        console.log("Chat existiert schon");
                    }
                    
                    else {
                        let chatId = 0;
                        const latestChat = await Chat.findOne().sort({ chatId: -1 });
                        if (latestChat != null) { chatId = latestChat.chatId + 1; }

                        console.log(chatId, " -- ", latestChat);

                        await Chat.create({
                            chatId:           chatId,
                            chatName:         data.body.chatName,
                            chatAuth:         data.body.chatAuth,
                            users:            [],
                            createdById:      user.userId,
                            createdByName:    user.username,
                            createdTimestamp: now,
                        });

                        const createdChat = await Chat.findOne({ chatId });
                        console.log("Created chat: " + createdChat);

                        replyPayload = {
                            header: "chat_creation_response",
                            statusCode: 1, // -- Chat-Erstellung erfolgreich
                            body: {
                                chatId:           createdChat.chatId,
                                chatName:         createdChat.chatName,
                                chatAuth:         createdChat.chatAuth,
                                createdById:      createdChat.createdById,
                                createdByName:    createdChat.createdByName,
                                createdTimestamp: createdChat.createdTimestamp,
                            },
                        };
                    }

                    break;
                }

                case "join_chat": {
                    console.log("User tries to join chatroom");
                    replyPayload = { header: "join_response", statusCode: 0 };
                    const authCode = await auth(data.userId, data.authToken);

                    switch (authCode) {
                        case 1: {
                            replyPayload = {
                                header: "join_response",
                                statusCode: 4, // -- Token passt nicht zu UserID
                            };

                            break;
                        }

                        case 2: {
                            replyPayload = {
                                header: "join_response",
                                statusCode: 5, // -- User nicht gefunden
                            };

                            break;
                        }

                        case 3: {
                            replyPayload = {
                                header: "join_response",
                                statusCode: 6, // -- Invalider Token
                                action: data
                            };

                            break;
                        }
                        
                        case 0: {
                            console.log("User tries to join chatroom");

                            const chatName = data.body.chatName;
                            console.log("chatName:", chatName);
                            const chat = await Chat.findOne({ chatName: chatName });
                            const user = await User.findOne({ userId: data.userId });
                            
                            if (chat == null) {
                                replyPayload.statusCode = 0; // -- Chat existiert nicht
                            }
                            
                            else if (chat.chatAuth !== data.body.chatAuth) {
                                replyPayload.statusCode = 1; // -- Falsches Passwort
                            }
                            
                            else if (chat.users.some((u) => u.userId === user.userId)) {
                                replyPayload.statusCode = 2; // -- User ist bereits Mitglied
                            }
                            
                            else {
                                chat.users.push(user._id);
                                chat.save();
                                await chat.populate({ path: "users",  select: "userId username createdTimestamp lastSeen" });

                                console.log(chat);

                                const userList = chat.users.map(u => ({
                                  userId: u.userId,
                                  username: u.username,
                                  joinedTimestamp: u.createdTimestamp,
                                  lastSeen: u.lastSeen
                                }));

                                console.log(userList);
                            
                                replyPayload.statusCode = 3; // -- Erfolgreich beigetreten
                                replyPayload.body = {
                                    chatId:           chat.chatId,
                                    chatName:         chat.chatName,
                                    chatAuth:         chat.chatAuth,
                                    users:            userList,
                                    createdById:      chat.createdById,
                                    createdByName:    chat.createdByName,
                                    createdTimestamp: chat.createdTimestamp,
                                };
                            }
                        
                            break;
                        }
                    }

                    break;
                }

                case "new_message": {
                    const authCode = await auth(data.userId, data.authToken);

                    switch (authCode) {
                        case 1: {
                            replyPayload = {
                                header: "message_response",
                                statusCode: 1, // -- Token passt nicht zu UserID
                            };

                            break;
                        }

                        case 2: {
                            replyPayload = {
                                header: "message_response",
                                statusCode: 2, // -- User nicht gefunden
                            };

                            break;
                        }

                        case 3: {
                            replyPayload = {
                                header: "message_response",
                                statusCode: 3, // -- Invalider Token
                                action: data
                            };

                            break;
                        }
                        
                        case 0: {
                            const now = new Date().toISOString();

                            let messageId = 0;
                            const latestMessage = await Message.findOne().sort({ messageId: -1 });
                            if (latestMessage != null) messageId = latestMessage.messageId + 1;

                            const chat = await Chat.findOne({ chatId: data.body.chatId }).populate("users", "userId");
                            let receiverIds = [];

                            if (chat != null) receiverIds = chat.users.map(u => u.userId).filter(id => id !== data.body.senderId);
                            else break;

                            await Message.create({
                                messageId:     messageId,
                                chatId:        data.body.chatId,
                                senderId:      data.body.senderId,
                                senderName:    data.body.senderName,
                                text:          data.body.text,
                                sentTimestamp: now,
                            
                                receivers: receiverIds.map(id => ({
                                  userId: id,
                                  received: false,
                                  receivedTimestamp: "",
                                })),
                            });
                        
                            const createdMessage = await Message.findOne({ messageId });
                            console.log(createdMessage);
                        
                            replyPayload = {
                                header: "message_response",
                                statusCode: 0,
                                body: {
                                    uId:           data.body.uId,
                                    oldMessageId:  data.body.messageId,
                                    newMessageId:  createdMessage.messageId,
                                    chatId:        createdMessage.chatId,
                                    senderId:      createdMessage.senderId,
                                    senderName:    createdMessage.senderName,
                                    text:          createdMessage.text,
                                    sentTimestamp: createdMessage.sentTimestamp,
                                }
                            };
                        
                            const broadcastPayload = {
                                header: "broadcast_message",
                                body: {
                                    messageId:     createdMessage.messageId,
                                    chatId:        createdMessage.chatId,
                                    senderId:      createdMessage.senderId,
                                    senderName:    createdMessage.senderName,
                                    text:          createdMessage.text,
                                    sentTimestamp: createdMessage.sentTimestamp,
                                    receiversList: createdMessage.receivers,
                                }
                            };

                            wss.broadcast(broadcastPayload);
                        
                            for (var index in createdMessage.receivers) {
                                let receiver = createdMessage.receivers[index];
                                if (receiver.userId == data.body.senderId) break;
                                let _user = await User.findOne({ userId: receiver.userId });
                                if (!_user) break;
                            
                                sendPushNotification(
                                    _user.fcmToken,
                                    chat,
                                    createdMessage.sentTimestamp
                                );
                            }

                            break;
                        }
                    }

                    break;
                }

                case "received_message": {
                    const authCode = await auth(data.userId, data.authToken);

                    switch (authCode) {
                        case 1: {
                            replyPayload = {
                                header: "force_signout", // -- Token passt nicht zu UserID
                            };

                            break;
                        }

                        case 2: {
                            replyPayload = {
                                header: "force_signout", // -- User nicht gefunden
                            };

                            break;
                        }

                        case 3: {
                            replyPayload = {
                                header: "received_message_response",
                                statusCode: 1, // -- Invalider Token
                                action: data
                            };

                            break;
                        }
                        
                        case 0: {
                            const messageId = data.body.messageId;

                            await Message.updateOne(
                              { messageId, "receivers.userId": data.body.receiverId },
                              {
                                $set: {
                                  "receivers.$.received": true,
                                  "receivers.$.receivedTimestamp": new Date().toISOString(),
                                },
                              }
                            );

                            break;
                        }
                    }

                    break;
                }

                case "sync_messages": {
                    const authCode = await auth(data.userId, data.authToken);

                    switch (authCode) {
                        case 1: {
                            replyPayload = {
                                header: "sync_messages_response",
                                statusCode: 1, // -- Token passt nicht zu UserID
                            };

                            break;
                        }

                        case 2: {
                            replyPayload = {
                                header: "sync_messages_response",
                                statusCode: 2, // -- User nicht gefunden
                            };

                            break;
                        }

                        case 3: {
                            replyPayload = {
                                header: "sync_messages_response",
                                statusCode: 3, // -- Invalider Token
                                action: data
                            };

                            break;
                        }
                        
                        case 0: {
                            const latestMessageId = data.body.latestId;

                            const messages = await Message.find({
                              messageId: { $gt: latestMessageId }
                            });

                            replyPayload = {
                                header: "sync_messages_response",
                                statusCode: 0,
                                messages: messages
                            }

                            break;
                        }
                    }

                    break;
                }
            }
        }
        
        catch (err) {
            console.log(err.toString());
        }

        if (!isEmptyObject(replyPayload)) {
            const enc = aesGcmEncrypt(this.client.sessionKey, JSON.stringify(replyPayload));
            this.client.send(JSON.stringify({ type: "enc", iv: enc.iv, data: enc.data, tag: enc.tag }));

            console.log("Server → (enc):", JSON.stringify(replyPayload));
        }
    }
}

async function auth(userId, token) {
    try {
        const payload = jwt.verify(token, SECRET_KEY);
        if (payload.userId !== userId) return 1; // -- Token passt nicht zu UserID

        const user = await User.findOne({ userId: userId });
        if (user == null) return 2; // -- User nicht gefunden

        if (user.userId == userId) return 0; // -- Erfolgreich authentifiziert
    }

    catch (err) {
        return 3; // -- Invalider Token
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