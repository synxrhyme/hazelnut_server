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

const { ChatScheme }      = require("./schemes/ChatScheme");
const { MessageScheme }   = require("./schemes/MessageScheme");
const { UserScheme }      = require("./schemes/UserScheme");

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const JWT_SECRET_KEY = process.env.JWT_SECRET;

const app = express();
app.listen(1001, () => console.log("HTTPS Server listening on port 1001"));
app.use(express.static(path.join(__dirname, "public")));

const dbConnection = mongoose.createConnection("mongodb://server:supersecuremongodbpassword@127.0.0.1:27017/hazelnut_db?authSource=admin");
const wss = new WebSocketServer({ port: 1002, maxPayload: 10 * 1024 });

const User    = dbConnection.model("User", UserScheme, "hazelnut_userdb");
const Message = dbConnection.model("Message", MessageScheme, "hazelnut_msgdb");
const Chat    = dbConnection.model("Chat", ChatScheme, "hazelnut_chatdb");

wss.on("connection", (client) => {
    console.log("New client connected");

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
        console.log("State:", state.value);
    });

    client.on("message", async (msg) => {
        const parsedMsg = JSON.parse(msg.toString());

        switch (parsedMsg.type) {
            case "ping":
                //service.send({ type: "WS_MESSAGE_PING",      parsed: parsedMsg });
                client.send(JSON.stringify({ type: "pong" }));
                break;
            case "key_exchange":
                console.log("Received mlkem_key message from client");
                service.send({ type: "WS_MESSAGE_MLKEM_KEY", parsed: parsedMsg });
                break;
            case "key_confirmation":
                console.log("Received key_confirmation message from client");
                service.send({ type: "WS_MESSAGE_CONFIRM",   parsed: parsedMsg });
                break;
            case "enc":
                const dec = await aesGcmDecrypt(client.sessionKey, parsedMsg.iv, parsedMsg.data, parsedMsg.tag);
                const decParsed = JSON.parse(dec);

                console.log("Received encrypted message from client:", dec);
                service.send({ type: "WS_MESSAGE_ENCRYPTED", parsed: decParsed });
                break;
            default:
                console.warn("Unknown message type:",        parsedMsg.type);
            
        }
    });

    client.on("close", () => {
        console.log("Connection closed");
    });
});

wss.broadcast = function broadcast(payload) {
    const receiversList = payload.body.receiversList;

    wss.clients.forEach((client) => {
        if (client.ready == true && receiversList.some(r => r.userId === client.userId)) {
            console.log("broadcasting to:", client.userId);

            const _enc = aesGcmEncrypt(client.sessionKey, JSON.stringify(payload));
            const response = JSON.stringify({ type: "enc", iv: _enc.iv, data: _enc.data, tag: _enc.tag });
            console.log("response", response);
            
            client.send(response);
        }
    });
};