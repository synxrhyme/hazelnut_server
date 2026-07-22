require('dotenv').config();

const { createActor }     = require("xstate");
const serviceAccount      = require("./serviceAccountKey.json");
const admin               = require("firebase-admin");
const mongoose            = require("mongoose");
const express             = require("express");
const path                = require("path");
const { WebSocketServer } = require("ws");

const { mainMachine }     = require("./machines/mainMachine");
const { aesGcmEncrypt, aesGcmDecrypt } = require('./util/CryptUtils');
const { rl, safeLog } = require("./util/ServerControl");

const { ChatScheme }      = require("./schemes/ChatScheme");
const { MessageScheme }   = require("./schemes/MessageScheme");
const { UserScheme }      = require("./schemes/UserScheme");

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const JWT_SECRET_KEY = process.env.JWT_SECRET;

const app = express();
app.listen(1001, () => safeLog("HTTPS Server listening on port 1001"));

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,          // disable auto-serving of index.html so our route controls it
  extensions: false,     // disable .html extension auto-resolution
}));

app.use('/fonts', express.static(path.join(__dirname, 'public', 'fonts'), {
    setHeaders(res, filePath) {
        if (filePath.endsWith('.woff2')) res.set('Content-Type', 'font/woff2');
        if (filePath.endsWith('.woff'))  res.set('Content-Type', 'font/woff');
    }
}));

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/download', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public',  'download.html'));
});

app.get('/legal', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public',  'legal.html'));
});

// 404 fallback
app.use((_req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

const dbConnection = mongoose.createConnection("mongodb://server:supersecuremongodbpassword@127.0.0.1:27017/hazelnut_db?authSource=admin");
const wss = new WebSocketServer({ port: 1002, maxPayload: 10 * 1024 });

const User    = dbConnection.model("User", UserScheme, "hazelnut_userdb");
const Message = dbConnection.model("Message", MessageScheme, "hazelnut_msgdb");
const Chat    = dbConnection.model("Chat", ChatScheme, "hazelnut_chatdb");

rl.prompt();

rl.on("line", async (line) => {
    const input = line.trim();
    const parts = input.split(" ");

    switch (parts[0]) {
        case "status":
            safeLog(`Server läuft, ${wss.clients.length} Clients verbunden`);
            break;
        
        case "delete_user": {
            const username = parts[1];
            
            const user = await User.findOne({ username });
            if (!user) {
                safeLog(`User ${username} nicht gefunden`);
                break;
            }
        
            try {
                await Promise.all([
                    User.deleteOne({ _id: user._id }),
                    Chat.updateMany(
                        { users: user._id },
                        { $pull: { users: user._id } }
                    ),
                    Message.deleteMany({ senderId: user.userId }), // oder user._id, je nach Schema
                ]);
                safeLog(`User ${username} vollständig gelöscht`);
            } catch (err) {
                safeLog(`Fehler beim Löschen von User ${username}:`, err);
            }

            break;
        }

        case "delete_chat": {
            const chatName = parts[1];
            
            const chat = await Chat.findOne({ chatName: chatName });
            if (!chat) {
                safeLog(`Chat ${chatName} nicht gefunden`);
                break;
            }

            try {
                await Promise.all([
                    Chat.deleteOne({ chatId: chat.chatId }),
                    Message.deleteMany({ chatId: chat._id }),
                ]);
                safeLog(`Chat ${chatName} vollständig gelöscht`);
            } catch (err) {
                safeLog(`Fehler beim Löschen von Chat ${chatName}:`, err);
            }

            break;
        }

        case "delete_all": {
            try {
                await Promise.all([
                    User.deleteMany({}),
                    Chat.deleteMany({}),
                    Message.deleteMany({}),
                ]);
                safeLog(`Alle Daten vollständig gelöscht`);
            } catch (err) {
                safeLog(`Fehler beim Löschen der Daten:`, err);
            }

            break;
        }

        case "reload": {
            wss.clients.forEach((client) => {
                client.close(1000, "Server reload");
            });
            
            safeLog("Alle Clients getrennt");
        }

        default:
            safeLog(`Unbekannter Befehl: ${input}`);
    }

    rl.prompt();
});

rl.on("close", () => {
    console.log("CLI beendet");
    process.exit(0);
});

wss.on("connection", (client) => {
    safeLog("New client connected");

    const service = createActor(mainMachine, {
        input: {
            wss:          wss,
            client:       client,
            dbConnection: dbConnection,
            jwtSecretKey: JWT_SECRET_KEY,

            userModel:    User,
            messageModel: Message,
            chatModel:    Chat
        }
    });

    service.start();

    service.subscribe((state) => {
        safeLog("State:", state.value);
    });

    client.on("message", async (msg) => {
        const parsedMsg = JSON.parse(msg.toString());

        switch (parsedMsg.type) {
            case "ping":
                //service.send({ type: "WS_MESSAGE_PING",      parsed: parsedMsg });
                client.send(JSON.stringify({ type: "pong" }));
                break;
            case "key_exchange":
                safeLog("Received mlkem_key message from client");
                service.send({ type: "WS_MESSAGE_MLKEM_KEY", parsed: parsedMsg });
                break;
            case "key_confirmation":
                safeLog("Received key_confirmation message from client");
                service.send({ type: "WS_MESSAGE_CONFIRM",   parsed: parsedMsg });
                break;
            case "enc":
                const dec = await aesGcmDecrypt(client.sessionKey, parsedMsg.iv, parsedMsg.data, parsedMsg.tag);
                const decParsed = JSON.parse(dec);

                safeLog("Received encrypted message from client:", dec);
                service.send({ type: "WS_MESSAGE_ENCRYPTED", parsed: decParsed });
                break;
            default:
                console.warn("Unknown message type:",        parsedMsg);
            
        }
    });

    client.on("close", () => {
        safeLog("Connection closed");
    });
});

module.exports = { wss, User, Message, Chat };