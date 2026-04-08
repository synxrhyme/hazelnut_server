const { createMachine, assign, forwardTo } = require("xstate");

const { handshakeMachine } = require("./handshakeMachine");
const { authMachine }      = require("./authMachine");
const { appMachine }       = require("./appMachine");

const mainMachine = createMachine(
    {
        id: 'connection',
        initial: 'waitingForInitialMessage',

        context: ({ input }) => ({
            wss:          input.wss          ?? undefined,
            client:       input.client       ?? undefined,
            dbConnection: input.dbConnection ?? undefined,
            jwtSecretKey: input.jwtSecretKey ?? undefined,

            initialMessage: null,

            userModel:    input.userModel    ?? undefined,
            messageModel: input.messageModel ?? undefined,
            chatModel:    input.chatModel    ?? undefined,
        }),

        states: {
            waitingForInitialMessage: {
                on: {
                    WS_MESSAGE_MLKEM_KEY: {
                        target: 'handshake',
                        actions: assign({
                            initialMessage: ({ event }) => {
                                return event.parsed;
                            }
                        })
                    }
                }
            },

            handshake: {
                invoke: {
                    id: "handshake",
                    src: handshakeMachine,
                    input: ({ context }) => ({
                        client:         context.client,
                        initialMessage: context.initialMessage,
                        identifier:     process.env.ID
                    }),
                    onDone: {
                        actions: [
                            () => console.log("Handshake successful, proceeding to authentication..."),
                            assign({
                                initialMessage: null
                            })
                        ],
                        target: 'auth'
                    },
                    onError: 'error.handshake'
                },
                on: {
                    WS_MESSAGE_CONFIRM: {
                        actions: "forwardToHandshake"
                    }
                }
            },

            auth: {
                invoke: {
                    id: "auth",
                    src: authMachine,
                    input: ({ context }) => ({
                        client:       context.client,
                        jwtSecretKey: context.jwtSecretKey,
                        identifier:   process.env.ID,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onDone: {
                        actions: [
                            () => console.log("Authentication successful, proceeding to application...")
                        ],
                        target: 'app'
                    },
                    onError: {
                        target: 'error.auth',
                        actions: ({ event }) => console.error("authMachine Fehler:", event.error)
                    }
                },
                on: {
                    WS_MESSAGE_ENCRYPTED: {
                        actions: [
                            () => console.log("Forwarding encrypted message to authMachine..."),
                            "forwardToAuth"
                        ]
                    },
                    TOKEN_EXPIRED: {
                        target: 'auth',
                        actions: () => console.log("Token abgelaufen, zurück zu auth...")
                    }
                }
            },

            app: {
                invoke: {
                    id: "app",
                    src: appMachine,
                    input: ({ context }) => ({
                        wss:          context.wss,
                        client:       context.client,
                        jwtSecretKey: context.jwtSecretKey,
                        identifier:   process.env.ID,

                        userModel:    context.userModel,
                        messageModel: context.messageModel,
                        chatModel:    context.chatModel,
                    }),
                    onError: {
                        target: 'error.app',
                        actions: ({ event }) => console.error("authMachine Fehler:", event.error)
                    }
                },
                on: {
                    WS_MESSAGE_ENCRYPTED: {
                        actions: [
                            () => console.log("Forwarding encrypted message to appMachine..."),
                            "forwardToApp"
                        ]
                    }
                }
            },

            error: {
                type: 'final',
                entry: ({ self }) => {
                    console.error("Fehler State erreicht:", JSON.stringify(self.getSnapshot().value));
                },
                states: {
                    handshake: {},
                    auth:      {},
                    app:       {}
                }
            }
        }
    },
    {
        actions: {
            forwardToHandshake: forwardTo("handshake"),
            forwardToAuth:      forwardTo("auth"),
            forwardToApp:       forwardTo("app"),
        }
    }
);

module.exports = { mainMachine };