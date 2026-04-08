const { createMachine, assign, fromPromise } = require("xstate");
const crypto                          = require("node:crypto");
const { deriveAesKey, aesGcmEncrypt } = require("../util/CryptUtils");

const handshakeMachine = createMachine(
    {
        id: 'handshake',
        initial: 'verifyingClientPayload',

        context: ({ input }) => ({
            client:     input.client         ?? undefined,
            data:       input.initialMessage ?? undefined,
            identifier: input.identifier     ?? undefined,

            clientEd25519PublicKey: null,
            clientIsVerifiedInitial: null,
            clientIsVerifiedConfirm: null,

            kem: null,
            signer: null,

            mlkemPublicKeyBytes: null,
            mldsaKeypair: null,
            ed25519Keypair: null,

            ciphertext: null,
            sharedSecret: null,
            aesKey: null,
            aesKeyHash: null,

            timestamp: null,
            messageToSign: null,

            mldsaPublicKeyRaw: null,
            mldsaSignature: null,
            
            ed25519DerKey: null,
            ed25519PublicKeyRaw: null,
            ed25519Signature: null,

            replyPayload: null,
            keyConfirmationMessage: null
        }),

        states: {
            verifyingClientPayload: {
                entry: [
                    //() => console.log("Verifying Client Payload..."),
                    assign({
                        clientEd25519PublicKey: ({ context }) => {
                            const rawPubKey = Buffer.from(context.data.publicKey, "base64");

                            const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
                            const spkiKey = Buffer.concat([spkiHeader, rawPubKey]);

                            return crypto.createPublicKey({
                                key: spkiKey,
                                format: "der",
                                type: "spki",
                            });
                        }
                    }),
                    assign({
                        clientIsVerifiedInitial: ({ context }) => {
                            try {
                                const messageToVerify = Buffer.concat([
                                    Buffer.from(context.data.publicKey, "base64"),
                                    Buffer.from(context.data.timestamp.toString(), "utf-8"),
                                ]);

                                const isValid = crypto.verify(
                                    null,
                                    messageToVerify,
                                    context.clientEd25519PublicKey,
                                    Buffer.from(context.data.authSignature, "base64")
                                );

                                return isValid;
                            } catch (error) {
                                console.error("Error occurred while verifying client payload:", error);
                                return false;
                            }
                        }
                    }),
                ],
                always: [
                    {
                        cond: ({ context }) => context.clientIsVerifiedInitial,
                        target: 'loadingLibs'
                    },
                    {
                        target: 'error.confirmationInvalid',
                        actions: () => console.log("Client payload verification failed, starting over!")
                    }
                ]
            },

            loadingLibs: {
                //entry: () => console.log("Loading cryptographic libraries..."),
                invoke: {
                    src: 'loadLibs',
                    onDone: {
                        target: 'validatingID',
                        actions: [
                            assign({
                                kem: ({ event })    => { return event.output.kem; },
                                signer: ({ event }) => { return event.output.signer; },
                            })
                        ]
                    },
                    onError: {
                        target: 'error.libLoadError',
                        actions: ({ context, event }) => console.error("loadLibs error", event)
                    }
                }
            },

            validatingID: {
                //entry: () => console.log("Validating ID..."),
                always: [
                    {
                        cond: 'isValidID',
                        target: 'generatingKeys'
                    },
                    { target: 'IDNoMatchError' }
                ],
                onError: 'error.validatingIDError'
            },

            generatingKeys: {
                entry: [
                    //() => console.log("Generating Keys..."),
                    assign({
                        mlkemPublicKeyBytes: ({ context }) => {
                            const mlkemPublicKeyBytes = new Uint8Array(Buffer.from(context.data.publicKey, "base64"));
                            return mlkemPublicKeyBytes;
                        },
                        mldsaKeypair: ({ context }) => {
                            const mldsaKeypair = context.signer.generateKeyPair();
                            return mldsaKeypair;
                        },
                        ed25519Keypair: ({ context }) => {
                            const ed25519Keypair = crypto.generateKeyPairSync("ed25519");
                            return ed25519Keypair;
                        }
                    })                    
                ],
                always: 'encapsulating',
                onError: 'error.keyGenError'
            },

            encapsulating: {
                entry: assign(({ context }) => {
                    //console.log("Encapsulating...");
                    const { ciphertext, sharedSecret } = context.kem.encapsulate(context.mlkemPublicKeyBytes);
                    return {
                        ...context,
                        ciphertext,
                        sharedSecret
                    };
                }),
                always:  'derivingKey',
                onError: 'error.encapsulatingError'
            },

            derivingKey: {
                //entry: () => console.log("Deriving AES key..."),
                invoke: {
                    src: 'derivingKey',
                    input: ({ context }) => ({
                        sharedSecret: context.sharedSecret
                    }),
                    onDone: {
                        target: 'signingKeyPacket',
                        actions: assign({
                            aesKey: ({ event }) => {
                                //console.log("Derived AES key successfully");
                                return event.output.key;
                            },
                            aesKeyHash: ({ event }) => {
                                //console.log("Calculated AES key hash successfully");
                                return event.output.hash;
                            }
                        }),
                    },
                    onError: 'error.derivingKeyError'
                }
            },

            signingKeyPacket: {
                entry: [
                    //() => console.log("Signing packet..."),
                    assign(({ context }) => {
                        const timestamp = Date.now();

                        const messageToSign = Buffer.concat([
                            Buffer.from(context.ciphertext),
                            Buffer.from(timestamp.toString())
                        ]);

                        const mldsaSignature = context.signer.sign(
                            new Uint8Array(messageToSign),
                            context.mldsaKeypair.secretKey
                        );

                        const ed25519Signature = crypto.sign(
                            null,
                            messageToSign,
                            context.ed25519Keypair.privateKey
                        );

                        const ed25519DerKey = context.ed25519Keypair.publicKey.export({
                            format: 'der',
                            type: 'spki'
                        });

                        const mldsaPublicKeyRaw   = context.mldsaKeypair.publicKey;
                        const ed25519PublicKeyRaw = ed25519DerKey.slice(-32);

                        return {
                            ...context,
                            timestamp,
                            messageToSign,
                            mldsaSignature,
                            ed25519Signature,
                            ed25519DerKey,
                            mldsaPublicKeyRaw,
                            ed25519PublicKeyRaw
                        };
                    })
                ],
                always: 'buildingResponse',
                onError: 'error.signingError'
            },

            buildingResponse: {
                entry: [
                    //() => console.log("Building response payload..."),
                    assign({
                        replyPayload: ({ context }) => {
                            return {
                                type: "key_exchange_response",
                                status: "success",
                                body: {
                                    ciphertext:        Buffer.from(context.ciphertext).toString("base64"),
                                    mldsaPublicKeyRaw: Buffer.from(context.mldsaKeypair.publicKey).toString("base64"),
                                    mldsaSignature:    Buffer.from(context.mldsaSignature).toString("base64"),
                                    ed25519PublicKey:  context.ed25519PublicKeyRaw.toString("base64"),
                                    ed25519Signature:  context.ed25519Signature.toString("base64"),
                                    timestamp:         context.timestamp
                                }
                            }
                        }
                    }),
                ],
                always: 'sendingPlain',
                onError: 'error.buildingResponseError'
            },

            sendingPlain: {
                entry: [
                    //() => console.log("Sending response to client..."),
                    assign({
                        client: ({ context }) => {
                            context.client.sessionKey = context.aesKey;
                            context.client.send(JSON.stringify(context.replyPayload));
                            return context.client;
                        }
                    })
                ],
                always: 'waitingForConfirmation',
                onError: 'error.sendingPlainError'
            },

            waitingForConfirmation: {
                //entry: () => console.log("Waiting for confirmation from client..."),
                on: {
                    WS_MESSAGE_CONFIRM: {
                        actions: assign({
                            keyConfirmationMessage: ({ event }) => event.parsed
                        }),
                        "target": "validatingConfirmation",
                    }
                },
                after: {
                    10000: { target: 'error.sendingPlainError' }
                }
            },

            validatingConfirmation: {
                entry: [
                    //() => console.log("Validating confirmation from client..."),
                    assign({
                        clientIsVerifiedConfirm: ({ context }) => {
                            const messageToVerify = Buffer.concat([
                                Buffer.from(context.keyConfirmationMessage.hash, "base64"),
                                Buffer.from(context.keyConfirmationMessage.timestamp.toString(), "utf-8")
                            ]);

                            const isValid = crypto.verify(
                                null,
                                messageToVerify,
                                context.clientEd25519PublicKey,
                                Buffer.from(context.keyConfirmationMessage.signature, "base64")
                            );

                            return isValid;
                        }
                    })
                ],
                always: [
                    {
                        cond: "isValidConfirmation",
                        target: "checkingConfirmationHash",
                        actions: ({ context }) => {
                            //console.log("Message signature valid, checking confirmation hash...");
                            context.client.sessionKey = context.aesKey;
                        }
                    },
                    {
                        target: "error.confirmationInvalid",
                        actions: () => console.log("Invalid confirmation received, starting over!")
                    }
                ]
            },

            checkingConfirmationHash: {
                always: [
                    {
                        cond: "isValidHash",
                        target: "informingClientOfSuccess",
                        actions: ({ context }) => {
                            //console.log("Confirmation valid, imforming client...");
                            context.client.sessionKey = context.aesKey;
                        }
                    },
                    {
                        target: "error.confirmationHashInvalid",
                        actions: () => console.log("Invalid confirmation hash received, starting over!")
                    }
                ]
            },

            informingClientOfSuccess: {
                invoke: {
                    src: fromPromise(async ({ input }) => {
                        const successMessage = {
                            header: "handshake_response",
                            body: { status: "success" }
                        };

                        const enc = await aesGcmEncrypt(input.sessionKey, JSON.stringify(successMessage));
                        const reply = JSON.stringify({ type: "enc", iv: enc.iv, data: enc.data, tag: enc.tag });
                        input.client.send(reply);

                        //console.log("Client informed of success, finished handshake!");
                    }),
                    input: ({ context }) => ({
                        client: context.client,
                        sessionKey: context.client.sessionKey
                    }),
                    onDone: 'done',
                    onError: 'error.informingClientError'
                }
            },

            done: {
                type: 'final',
                output: ({ context }) => ({
                    sessionKey: context.aesKey
                })
            },

            IDNoMatchError: {
                entry: ({ context }) => {
                    console.error("Ungültige ID im Handshake");
                    context.client.close();
                },
                type: 'final'
            },

            error: {
                initial: "unknown",
                type: "final",
                states: {
                    unknown:                 {},
                    confirmationInvalid:     {},
                    libLoadError:            {},
                    validatingIDError:       {},
                    keyGenError:             {},
                    encapsulatingError:      {},
                    derivingKeyError:        {},
                    signingError:            {},
                    buildingResponseError:   {},
                    sendingPlainError:       {},
                    confirmationInvalid:     {},
                    confirmationHashInvalid: {},
                    informingClientError:    {}
                },
                entry: ({ context, self }) => {
                    console.error("Handshake Fehler:", self.getSnapshot().value);
                    context.client.close();
                    throw new Error(`Handshake failed at state: ${self.getSnapshot().value}`);
                }
            }
        }
    },
    {
        actors: {
            loadLibs: fromPromise(async () => {
                const liboqs = await import("@oqs/liboqs-js");

                const kem = await liboqs.createMLKEM768();
                const signer = await liboqs.createMLDSA65();

                return { kem, signer };
            }),

            derivingKey: fromPromise(async ({ input }) => {
                try {
                    const key = await deriveAesKey(Buffer.from(input.sharedSecret));
                    const algo = crypto.createHash('sha512');
                    algo.update(key);
                    const hash = algo.digest('base64');
                    return { key, hash };
                } catch (error) {
                    console.error("Error occurred while deriving key:", error);
                    throw error;
                }
            }),

            processHandshakeMessage: async (context, event) => {
                const msg = event.data

                return {
                    type: msg.type,
                    payload: msg
                };
            },
        },

        guards: {
            isValidID: ({ context }) => {
                const algo = crypto.createHash('sha512');
                algo.update(context.identifier);
                const hash = algo.digest('base64');
                return context.data.id === hash;
            },
            isValidConfirmation: ({ context }) => context.clientIsVerifiedConfirm === true,
            isValidHash: ({ context, event }) => event.hash?.toString() === context.aesKeyHash
        }
    }
);

module.exports = { handshakeMachine };