const jwt = require("jsonwebtoken");
const { createMachine, assign, fromPromise } = require("xstate");
const { aesGcmEncrypt } = require("../util/CryptUtils");
const { generateAuthToken, generateUserID, generateRefreshToken } = require("../util/TokenGeneration");

const authMachine = createMachine(
    {
        id: 'auth',
        initial: 'idle',

        context: ({ input }) => ({
            client:       input.client       ?? undefined,
            identifier:   input.identifier   ?? undefined,
            jwtSecretKey: input.jwtSecretKey ?? undefined,

            signupData: null,
            loginData: null,
            tokenRefreshData: null,

            userModel:    input.userModel    ?? undefined,
            messageModel: input.messageModel ?? undefined,
            chatModel:    input.chatModel    ?? undefined,
        }),

        states: {
            idle: {
                entry: () => console.log("Waiting for authentication request..."),
                on: {
                    WS_MESSAGE_ENCRYPTED: [
                        {
                            guard: ({ event }) => event.parsed?.header === "auth" && event.parsed?.body?.type === "signup",
                            target: "waitingForSignup",
                        },
                        {
                            guard: ({ event }) => event.parsed?.header === "auth" && event.parsed?.body?.type === "login",
                            target: "authenticating",
                            actions: assign({
                                loginData: ({ event }) => event.parsed?.body
                            })
                        },
                        {
                            guard: ({ event }) => event.parsed?.header === "refresh_request",
                            target: "tokenRefresh",
                            actions: assign({
                                tokenRefreshData: ({ event }) => event.parsed?.body
                            })
                        },
                        {
                            target: "error.unknownRequest"
                        }
                    ]
                }
            },

            waitingForSignup: {
                entry: () => console.log("Waiting for signup request..."),
                on: {
                    WS_MESSAGE_ENCRYPTED: {
                        guard: ({ event }) => event.parsed?.header === "auth_request" && event.parsed?.body?.type === "signup",
                        target: "signup",
                        actions: [
                            () => console.log("Received signup request, processing..."),
                            assign({
                                signupData: ({ event }) => event.parsed?.body
                            })
                        ]                    }
                }
            },

            signup: {
                invoke: {
                    id: "signup",
                    src: "signup",
                    input: ({ context }) => ({
                        client:       context.client,
                        signupData:   context.signupData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: 'authenticatedThroughSignup',
                        actions: async ({ event, context }) => {
                            const replyPayload = event.output;
                            console.log("Signup successful, sending encrypted response:", replyPayload);

                            const encryptedReply = await aesGcmEncrypt(
                                context.client.sessionKey,
                                JSON.stringify(replyPayload)
                            );

                            context.client.send(JSON.stringify({
                                type: "enc",
                                iv: encryptedReply.iv,
                                data: encryptedReply.data,
                                tag: encryptedReply.tag
                            }));
                        }
                    },
                    onError: 'error.signup'
                }
            },

            authenticating: {
                invoke: {
                    id: "authenticating",
                    src: "authenticating",
                    input: ({ context }) => ({
                        client:       context.client,
                        loginData:    context.loginData,
                        identifier:   context.identifier,
                        jwtSecretKey: context.jwtSecretKey,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        target: 'authenticated',
                        actions: async ({ event, context }) => {
                            const replyPayload = event.output;
                            console.log("Authentication finished, sending encrypted response:", replyPayload);

                            const encryptedReply = await aesGcmEncrypt(
                                context.client.sessionKey,
                                JSON.stringify(replyPayload)
                            );

                            context.client.send(JSON.stringify({
                                type: "enc",
                                iv: encryptedReply.iv,
                                data: encryptedReply.data,
                                tag: encryptedReply.tag
                            }));
                        }
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_EXPIRED",
                            target: 'waitingForTokenRefresh',
                            actions: async ({ context }) => {
                                const replyPayload = {
                                    header: "auth_response",
                                    status: "token_invalid",
                                    body: {
                                        timestamp: Date.now()
                                    },
                                }

                                console.log("Token expired, sending response:", replyPayload);

                                const encryptedReply = await aesGcmEncrypt(
                                    context.client.sessionKey,
                                    JSON.stringify(replyPayload)
                                );

                                context.client.send(JSON.stringify({
                                    type: "enc",
                                    iv: encryptedReply.iv,
                                    data: encryptedReply.data,
                                    tag: encryptedReply.tag
                                }));
                            }
                        },
                        {
                            guard: ({ event }) => event.error?.code === "TOKEN_INVALID",
                            target: 'error.tokenInvalid'
                        },
                        {
                            target: 'error.authenticating'
                        }
                    ]
                }
            },

            waitingForTokenRefresh: {
                entry: () => console.log("Waiting for refresh token request..."),
                on: {
                    WS_MESSAGE_ENCRYPTED: {
                        guard: ({ event }) => event.parsed?.header === "refresh_request",
                        target: "tokenRefresh",
                        actions: [
                            () => console.log("Received refresh token, processing..."),
                            assign({
                                tokenRefreshData: ({ event }) => event.parsed?.body
                            })
                        ]
                    }
                }
            },

            tokenRefresh: {
                invoke: {
                    id: "tokenRefresh",
                    src: fromPromise(async ({ input }) => {
                        // -- REFRESH TOKEN KÖNNTE GEKLAUT SEIN - TODO
                        const User = input.userModel;
                        
                        const userId = input.tokenRefreshData.userId;
                        const user = await User.findOne({ userId });
                    
                        const now = new Date().toISOString();
                    
                        if (user == null) {
                            return {
                                header: "refresh_response",
                                status: "user_invalid",
                                body: {
                                    timestamp: now,
                                }
                            }
                        }
                    
                        else if (user.userId === userId) {
                            const newAuthToken = generateAuthToken(userId, input.jwtSecretKey);
                    
                            return {
                                header: "refresh_response",
                                status: "valid",
                                body: {
                                    authToken: newAuthToken,
                                    timestamp: now
                                }
                            }
                        }
                    }),
                    input: ({ context }) => ({
                        client:           context.client,
                        tokenRefreshData: context.tokenRefreshData,
                        identifier:       context.identifier,
                        jwtSecretKey:     context.jwtSecretKey,

                        userModel:        context.userModel,
                        messageModel:     context.messageModel,
                        chatModel:        context.chatModel,
                    }),
                    onDone: {
                        target: 'idle',
                        actions: async ({ event, context }) => {
                            const replyPayload = event.output;
                            console.log("Refresh finished, sending encrypted response:", replyPayload);

                            const encryptedReply = await aesGcmEncrypt(
                                context.client.sessionKey,
                                JSON.stringify(replyPayload)
                            );

                            context.client.send(JSON.stringify({
                                type: "enc",
                                iv: encryptedReply.iv,
                                data: encryptedReply.data,
                                tag: encryptedReply.tag
                            }));
                        }
                    },
                    onError: [
                        {
                            guard: ({ event }) => event.error?.code === "USER_INVALID",
                            target: 'error.refreshUserInvalid',
                            actions: async ({ context }) => {
                                const replyPayload = {
                                    header: "refresh_response",
                                    status: "user_invalid",
                                    body: {
                                        timestamp: now,
                                    }
                                }

                                console.log("Refresh user invalid, sending encrypted response:", replyPayload);

                                const encryptedReply = await aesGcmEncrypt(
                                    context.client.sessionKey,
                                    JSON.stringify(replyPayload)
                                );

                                context.client.send(JSON.stringify({
                                    type: "enc",
                                    iv: encryptedReply.iv,
                                    data: encryptedReply.data,
                                    tag: encryptedReply.tag
                                }));
                            }
                        },
                        {
                            target: 'error.refresh'
                        }
                    ]
                }
            },

            authenticatedThroughSignup: {
                type: 'final'
            },

            authenticated: {
                type: 'final'
            },

            error: {
                initial: "unknown",
                type: "final",
                states: {
                    unknown:            {},
                    unknownRequest:     {},
                    signup:             {},
                    authenticating:     {},
                    tokenInvalid:       {},
                    refresh:            {},
                    refreshUserInvalid: {},
                },
                entry: ({ context, self }) => {
                    console.error("Auth Fehler:", self.getSnapshot().value);
                    context.client.close();
                    throw new Error(`Auth failed at state: ${self.getSnapshot().value}`);
                }
            }
        }
    },
    {
        actors: {
            signup: fromPromise(async ({ input }) => {
                try {
                    console.log("Processing signup...");
                    const User = input.userModel;
                    const findUsername = await User.findOne({ username: input.signupData.username });

                    if (findUsername !== null) {
                        return {
                            header: "registration_response",
                            status: "username_taken",
                        }
                    }

                    const findFcmToken = await User.findOne({ fcmToken: input.signupData.fcmToken });
                
                    if (findFcmToken !== null) {
                        return {
                            header: "registration_response",
                            status: "app_already_registered",
                        }
                    }

                    const now = new Date().toISOString();
                    const userId = generateUserID(input.signupData.fcmToken);
                
                    await User.create({
                        userId:           userId,
                        username:         input.signupData.username,
                        fcmToken:         input.signupData.fcmToken,
                        refreshToken:     generateRefreshToken(),
                        createdTimestamp: now,
                    });
                
                    const createdUser = await User.findOne({ userId });
                    console.log("Created user: " + createdUser);
                
                    return {
                        header: "registration_response",
                        status: "success",
                        body: {
                            userId:            createdUser.userId,
                            username:          createdUser.username,
                            fcmToken:          createdUser.fcmToken,
                            authToken:         generateAuthToken(createdUser.userId, input.jwtSecretKey),
                            refreshToken:      createdUser.refreshToken,
                            createdTimestamp:  createdUser.createdTimestamp,
                        }
                    }
                } catch (error) {
                    console.error("Error during signup process:", error);
                    throw error;
                }
            }),
            authenticating: fromPromise(async ({ input }) => {
                console.log("Autheticating...")
                try {
                    const User = input.userModel;
                    const payload = jwt.verify(input.loginData?.token, input.jwtSecretKey);
                    const userId = input.loginData?.userId;
                    
                    if (payload.userId !== userId) {
                        console.log("Token passt nicht zu UserID.");
                    
                        return {
                            header: "auth_response",
                            status: "token_invalid",
                            body: {
                                timestamp: Date.now()
                            },
                        }
                    }
                
                    else if (payload.userId === userId) {
                        const user = await User.findOne({ userId });
                    
                        if (user == null) {
                            console.log("User nicht gefunden.");
                        
                            return {
                                header: "auth_response",
                                status: "user_invalid",
                                body: {
                                    timestamp: Date.now()
                                },
                            }
                        }
                    
                        else if (user.userId === userId) {
                            input.client.userId = userId;
                            input.client.ready = true;

                            await User.updateOne(
                                { userId: userId },
                                { $set: { online: true } }
                            );

                            return {
                                header: "auth_response",
                                status: "valid",
                                body: {
                                    timestamp: Date.now()
                                }
                            }
                        }
                    }   
                }

                catch (err) {
                    if (err.name === "TokenExpiredError") {
                        throw Object.assign(new Error("TokenExpired"), { code: "TOKEN_EXPIRED" });
                    }
                    
                    else if (err.name === "JsonWebTokenError") {
                        throw Object.assign(new Error("TokenInvalid"), { code: "TOKEN_INVALID" });
                    }
                    
                    else {
                        throw err;
                    }
                }
            }),
        },
        guards: {
            isSignupRequest: ({ context }) => context.isSignupRequest,
            isLoginRequest:  ({ context }) => context.isLoginRequest,
        }
    }
);

module.exports = { authMachine };