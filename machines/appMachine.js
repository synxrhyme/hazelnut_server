const { createMachine, fromPromise, assign, sendParent } = require("xstate");
const { sendPushNotification, auth, broadcast } = require("../util/OtherUtil");
const { aesGcmEncrypt } = require("../util/CryptUtils");
const { safeLog } = require("../util/ServerControl");
const { StatusCodes } = require("../schemes/StatusCodes");

const appMachine = createMachine(
    {
        id: 'app',
        initial: 'idle',

        context: ({ input }) => ({
            wss:          input.wss          ?? undefined,
            client:       input.client       ?? undefined,
            dbConnection: input.dbConnection ?? undefined,
            jwtSecretKey: input.jwtSecretKey ?? undefined,

            currentMessage: null,
            pendingPayload: null,

            userModel:    input.userModel    ?? undefined,
            messageModel: input.messageModel ?? undefined,
            chatModel:    input.chatModel    ?? undefined,
        }),

        states: {
            idle: {
                entry: [
                    () => safeLog("Waiting for app request..."),
                    assign({ currentMessage: null, pendingPayload: null })
                ],
                on: {
                    WS_MESSAGE_ENCRYPTED: "processingMessage"
                }
            },

            processingMessage: {
                initial: "authenticating",
                states: {
                    authenticating: {
                        invoke: {
                            src: "authenticatingMessage",
                            input: ({ context, event }) => ({
                                userModel: context.userModel,
                                chatModel: context.chatModel,
                                data: event.output
                            }),
                            onDone: [
                                {
                                    guard: ({ event }) => event.output.needsResponse === true,
                                    target: "#sendingResponse",
                                    actions: assign({
                                        pendingPayload: ({ event }) => event.output.action
                                    })
                                },
                                {
                                    target: "routing",
                                    actions: assign({
                                        currentMessage: ({ event }) => event.output.message
                                    })
                                }
                            ],
                            onError: "#error.authFailed"
                        }
                    },

                    routing: {
                        always: [
                            {
                                guard: ({ context }) => context.currentMessage?.header === "create_chat",
                                target: "#creatingChat"
                            },
                            {
                                guard: ({ context }) => context.currentMessage?.header === "join_chat",
                                target: "#addingUserToChat"
                            },
                            {
                                guard: ({ context }) => context.currentMessage?.header === "new_message",
                                target: "#handlingNewMessage"
                            },
                            {
                                guard: ({ context }) => context.currentMessage?.header === "received_message",
                                target: "#handlingReceivedMessage"
                            },
                            {
                                guard: ({ context }) => context.currentMessage?.header === "sync_messages",
                                target: "#syncingMessages"
                            },
                            { target: "#error.unknownRequest" }
                        ]
                    },
                }
            },

            creatingChat: {
                invoke: {
                    id: "creatingChat",
                    src: "createChat",
                    input: ({ context }) => ({
                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        data:         context.currentMessage,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: "sendingResponse",
                        actions: assign({
                            pendingPayload: ({ event }) => event.output
                        })
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: "sendingTokenExpired",
                            actions: assign({
                                pendingPayload: ({ event }) => event.error.payload
                            })
                        },
                        { 
                            target: "error.creatingChat",
                            actions: ({ event }) => console.error("creatingChat ERROR:", event) // ← hinzufügen
                        }
                    ]
                }
            },

            addingUserToChat: {
                invoke: {
                    id: "addingUserToChat",
                    src: "joinChat",
                    input: ({ context }) => ({
                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        data:         context.currentMessage,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: "sendingResponse",
                        actions: assign({
                            pendingPayload: ({ event }) => event.output
                        })
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: "sendingTokenExpired",
                            actions: assign({
                                pendingPayload: ({ event }) => event.error.payload
                            })
                        },
                        { target: "error.addingUserToChat" }
                    ]
                }
            },

            handlingNewMessage: {
                invoke: {
                    id: "handlingNewMessage",
                    src: "newMessage",
                    input: ({ context }) => ({
                        wss:          context.wss,

                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        data:         context.currentMessage,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: "sendingResponse",
                        actions: assign({
                            pendingPayload: ({ event }) => event.output
                        })
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: "sendingTokenExpired",
                            actions: assign({
                                pendingPayload: ({ event }) => event.error.payload
                            })
                        },
                        { target: "error.handlingNewMessage" }
                    ]
                }
            },

            handlingReceivedMessage: {
                invoke: {
                    id: "handlingReceivedMessage",
                    src: "receivedMessage",
                    input: ({ context }) => ({
                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        data:         context.currentMessage,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: "sendingResponse",
                        actions: assign({
                            pendingPayload: ({ event }) => event.output
                        })
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: "sendingTokenExpired",
                            actions: assign({
                                pendingPayload: ({ event }) => event.error.payload
                            })
                        },
                        { target: "error.handlingReceivedMessage" }
                    ]
                }
            },

            syncingMessages: {
                invoke: {
                    id: "syncingMessages",
                    src: "syncMessages",
                    input: ({ context }) => ({
                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        data:         context.currentMessage,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: "sendingResponse",
                        actions: assign({
                            pendingPayload: ({ event }) => event.output
                        })
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: "sendingTokenExpired",
                            actions: assign({
                                pendingPayload: ({ event }) => event.error.payload
                            })
                        },
                        { target: "error.syncingMessages" }
                    ]
                }
            },

            sendingTokenExpired: {
                invoke: {
                    src: fromPromise(async ({ input }) => {
                        const enc = await aesGcmEncrypt(
                            input.client.sessionKey,
                            JSON.stringify(input.payload)
                        );

                        input.client.send(JSON.stringify({
                            type: "enc",
                            iv: enc.iv,
                            data: enc.data,
                            tag: enc.tag
                        }));
                    }),
                    input: ({ context }) => ({
                        client:  context.client,
                        payload: context.pendingPayload
                    }),
                    onDone: {
                        actions: sendParent({ type: 'TOKEN_EXPIRED' }),
                        target: 'idle'
                    },
                    onError: { target: 'idle' }
                }
            },

            sendingResponse: {
                invoke: {
                    src: fromPromise(async ({ input }) => {
                        const replyPayload = input.payload;
                        safeLog("Command finished, sending encrypted response:", replyPayload);

                        const encryptedReply = await aesGcmEncrypt(
                            input.client.sessionKey,
                            JSON.stringify(replyPayload)
                        );

                        input.client.send(JSON.stringify({
                            type: "enc",
                            iv: encryptedReply.iv,
                            data: encryptedReply.data,
                            tag: encryptedReply.tag
                        }));
                    }),
                    input: ({ context }) => ({
                        client:  context.client,
                        payload: context.pendingPayload
                    }),
                    onDone:  { target: "idle" },
                    onError: { target: "error.sendingResponseError" }
                }
            },

            error: {
                initial: "unknown",
                type: "final",
                states: {
                    unknown:                 {},
                    unknownRequest:          {},
                    authFailed:              {},
                    creatingChat:            {},
                    addingUserToChat:        {},
                    handlingNewMessage:      {},
                    handlingReceivedMessage: {},
                    syncingMessages:         {},
                    sendingResponseError:    {},
                },
                entry: ({ context, self }) => {
                    console.error("App Fehler:", self.getSnapshot().value);
                    context.client.close();
                    throw new Error(`App failed at state: ${self.getSnapshot().value}`);
                },
            }
        }
    },

    {
        actors: {
            authenticatingMessage: fromPromise(async ({ input }) => {
                safeLog("authenticating:", input.data);
                
                const User = input.userModel;
                const userId = input.data.userId;
                const authCode = await auth(User, userId, input.data.authToken);

                switch (authCode) {
                    case 1:
                        return {
                            needsResponse: true,
                            payload: {
                                header: "auth_response",
                                statusCode: StatusCodes.INVALID_TOKEN_FOR_USERID
                            }
                        };
                    
                    case 2:
                        return {
                            needsResponse: true,
                            payload: {
                                header: "auth_response",
                                statusCode: StatusCodes.USER_NOT_FOUND
                            }
                        };
                    
                    case 3:
                        return {
                            needsResponse: true,
                            payload: {
                                header: "auth_response",
                                statusCode: StatusCodes.AUTH_TOKEN_EXPIRED,
                                action: input.data
                            }
                        };
                    
                    case 4:
                        throw new Error("Authentication error");
                    
                    case 0:
                        return {
                            needsResponse: false,
                            message: input.data
                        };
                    
                    default:
                        throw new Error(`Unexpected authCode: ${authCode}`);
                }
            }),

            createChat: fromPromise(async ({ input }) => {
                safeLog("User tries to create chatroom");

                const User = input.userModel;
                const Chat = input.chatModel;

                const userId = input.data.userId;
                const authCode = await auth(User, userId, input.data.authToken);

                safeLog("User creates new chatroom");

                const now = new Date().toISOString();
                const user = await User.findOne({ userId: userId });

                if (!user) {
                    throw new Error("Invalid user!");
                }
            
                if (await Chat.findOne({ chatName: input.data.body.chatName }) != null) {
                    safeLog("Chat existiert schon");
                
                    return {
                        header: "chat_creation_response",
                        statusCode: StatusCodes.CHAT_ALREADY_EXISTS
                    }
                }

                else {
                    let chatId = 0;
                    const latestChat = await Chat.findOne().sort({ chatId: -1 });
                
                    if (latestChat != null) {
                        chatId = latestChat.chatId + 1;
                    }
                
                    safeLog(chatId, " -- ", latestChat);
                
                    await Chat.create({
                        chatId:           chatId,
                        chatName:         input.data.body.chatName,
                        chatAuth:         input.data.body.chatAuth,
                        users:            [],
                        createdById:      user.userId,
                        createdByName:    user.username,
                        createdTimestamp: now,
                    });
                
                    const createdChat = await Chat.findOne({ chatId });
                    safeLog("Created chat: " + createdChat);
                
                    return {
                        header: "chat_creation_response",
                        statusCode: StatusCodes.CHAT_CREATION_SUCCESSFUL,
                        body: {
                            chatId:           createdChat.chatId,
                            chatName:         createdChat.chatName,
                            chatAuth:         createdChat.chatAuth,
                            createdById:      createdChat.createdById,
                            createdByName:    createdChat.createdByName,
                            createdTimestamp: createdChat.createdTimestamp,
                        },
                    }
                }
            }), 

            joinChat: fromPromise(async ({ input }) => {
                safeLog("User tries to join chatroom");

                const User = input.userModel;
                const Chat = input.chatModel;
                
                const userId = input.data.userId;
                const authCode = await auth(User, userId, input.data.authToken);

                safeLog("User tries to join chatroom");

                const chatName = input.data.body.chatName;
                safeLog("chatName:", chatName);

                const chat = await Chat.findOne({ chatName: chatName });
                const user = await User.findOne({ userId: userId });

                if (chat == null) {
                    return {
                        header: "join_response",
                        statusCode: StatusCodes.CHAT_NOT_FOUND
                    }
                }

                else if (chat.chatAuth !== input.data.body.chatAuth) {
                    return {
                        header: "join_response",
                        statusCode: StatusCodes.CHAT_WRONG_PASSWORD
                    }
                }

                else if (chat.users.some((u) => u.userId === user.userId)) {
                    return {
                        header: "join_response",
                        statusCode: StatusCodes.CHAT_ALREADY_JOINED
                    }
                }

                else {
                    chat.users.push(user._id);
                    chat.save();

                    await chat.populate({ path: "users",  select: "userId username createdTimestamp lastSeen" });
                    safeLog(chat);

                    const userList = chat.users.map(u => ({
                        userId:          u.userId,
                        username:        u.username,
                        joinedTimestamp: u.createdTimestamp,
                        lastSeen:        u.lastSeen
                    }));

                    safeLog(userList);

                    return {
                        header: "join_response",
                        statusCode: StatusCodes.CHAT_JOIN_SUCCESSFUL,
                        body: {
                            chatId:           chat.chatId,
                            chatName:         chat.chatName,
                            chatAuth:         chat.chatAuth,
                            users:            userList,
                            createdById:      chat.createdById,
                            createdByName:    chat.createdByName,
                            createdTimestamp: chat.createdTimestamp,
                        }
                    }
                }
            }),

            newMessage: fromPromise(async ({ input }) => {
                const userId = input.data.userId;
                const chatId = input.data.body.chatId;

                const User = input.userModel;
                const Chat = input.chatModel;
                const Message = input.messageModel;
                
                const authCode = await auth(User, userId, input.data.authToken);

                const now = new Date().toISOString();

                let messageId = 0;
                const latestMessage = await Message.findOne().sort({ messageId: -1 });
                if (latestMessage != null) messageId = latestMessage.messageId + 1;

                const chat = await Chat.findOne({ chatId: chatId }).populate("users", "userId");
                let receiverIds = [];

                if (chat != null) receiverIds = chat.users.map(u => u.userId).filter(id => id !== input.data.body.senderId);
                else throw new Error("Chat not found!");

                await Message.create({
                    messageId:     messageId,
                    chatId:        input.data.body.chatId,
                    senderId:      input.data.body.senderId,
                    senderName:    input.data.body.senderName,
                    text:          input.data.body.text,
                    sentTimestamp: now,
                
                    receivers: receiverIds.map(id => ({
                        userId: id,
                        received: false,
                        receivedTimestamp: "",
                    })),
                });
                
                const createdMessage = await Message.findOne({ messageId });
                safeLog(createdMessage);

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

                broadcast(input.wss, broadcastPayload);
                
                for (var index in createdMessage.receivers) {
                    let receiver = createdMessage.receivers[index];
                    if (receiver.userId == input.data.body.senderId) continue;
                    let _user = await User.findOne({ userId: receiver.userId });
                    if (!_user) continue;
                
                    sendPushNotification(
                        _user.fcmToken,
                        chat,
                        createdMessage.sentTimestamp
                    );
                }
                
                return {
                    header: "message_response",
                    statusCode: StatusCodes.MESSAGE_RECEIVED,
                    body: {
                        uId:           input.data.body.uId,
                        oldMessageId:  input.data.body.messageId,
                        newMessageId:  createdMessage.messageId,
                        chatId:        createdMessage.chatId,
                        senderId:      createdMessage.senderId,
                        senderName:    createdMessage.senderName,
                        text:          createdMessage.text,
                        sentTimestamp: createdMessage.sentTimestamp,
                    }
                }
            }),

            receivedMessage: fromPromise(async ({ input }) => {
                const User = input.userModel;
                const Message = input.messageModel;
                
                const userId = input.data.userId;
                const authCode = await auth(User, userId, input.data.authToken);
                
                const messageId = input.data.body.messageId;

                await Message.updateOne(
                    { messageId, "receivers.userId": input.data.body.receiverId },
                    {
                        $set: {
                            "receivers.$.received": true,
                            "receivers.$.receivedTimestamp": new Date().toISOString(),
                        },
                    }
                );
            }),

            syncMessages: fromPromise(async ({ input }) => {
                const User = input.userModel;
                const Message = input.messageModel;
                
                const userId = input.data.userId;
                const authCode = await auth(User, userId, input.data.authToken);

                const missed = await Message.find({
                    receivers: { $elemMatch: { userId: userId, received: false } }
                })
                .sort({ messageId: 1 })
                .lean();

                return {
                    header: "sync_messages_response",
                    statusCode: StatusCodes.SYNC_MESSAGES_SUCCESS,
                    body: { messages: missed }
                }
            })
        }
    }
);

module.exports = { appMachine };