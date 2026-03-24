import { createMachine, assign } from "xstate";

export const protocolMachine = createMachine({
  id: "protocol",
  initial: "connected",

  context: {
    sessionKey: null,
    userId: null,
    reply: null
  },

  states: {
    connected: {
      on: {
        AUTH: {
          target: "handleAuth"
        },
        REGISTRATION: {
          target: "handleRegistration"
        },
        REFRESH: {
          target: "handleRefresh"
        },
        IMAGE_UPLOAD: {
          target: "handleImageUpload"
        },
        CREATE_CHAT: {
          target: "handleCreateChat"
        },
        JOIN_CHAT: {
          target: "handleJoinChat"
        },
        NEW_MESSAGE: {
          target: "handleNewMessage"
        },
        RECEIVED_MESSAGE: {
          target: "handleReceivedMessage"
        },
        SYNC_MESSAGES: {
          target: "handleSyncMessages"
        }
      }
    },

    /* ---------------- AUTH ---------------- */
    handleAuth: {
      invoke: {
        src: "authService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        },
        onError: {
          target: "connected",
          actions: assign({
            reply: () => ({
              header: "auth_response",
              status: "token_invalid",
              body: { timestamp: Date.now() }
            })
          })
        }
      }
    },

    /* ------------- REGISTRATION ------------ */
    handleRegistration: {
      invoke: {
        src: "registrationService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    },

    /* ---------------- REFRESH -------------- */
    handleRefresh: {
      invoke: {
        src: "refreshService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    },

    /* ------------- IMAGE UPLOAD ------------ */
    handleImageUpload: {
      invoke: {
        src: "imageUploadService",
        onDone: "connected"
      }
    },

    /* ------------- CREATE CHAT ------------- */
    handleCreateChat: {
      invoke: {
        src: "createChatService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    },

    /* -------------- JOIN CHAT -------------- */
    handleJoinChat: {
      invoke: {
        src: "joinChatService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    },

    /* ------------ NEW MESSAGE -------------- */
    handleNewMessage: {
      invoke: {
        src: "newMessageService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    },

    /* ----------- RECEIVED MESSAGE ---------- */
    handleReceivedMessage: {
      invoke: {
        src: "receivedMessageService",
        onDone: "connected"
      }
    },

    /* ------------ SYNC MESSAGES ------------ */
    handleSyncMessages: {
      invoke: {
        src: "syncMessagesService",
        onDone: {
          target: "connected",
          actions: assign({ reply: (_, e) => e.data })
        }
      }
    }
  }
});