require('dotenv').config();

const { aesGcmEncrypt } = require("./util/CryptUtils");
const { UserScheme }    = require("./schemes/UserScheme");

const { KyberHandler }            = require("./handler/KyberHandler");
const { PingHandler }             = require("./handler/PingHandler");
const { EncryptedMessageHandler } = require("./handler/EncryptedMessageHandler");

const serviceAccount      = require("./serviceAccountKey.json");
const admin               = require("firebase-admin");
const mongoose            = require("mongoose");
const express             = require("express");
const path                = require("path");
const { WebSocketServer } = require("ws");

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const SECRET_KEY = process.env.JWT_SECRET;

const app = express();
app.listen(1001, () => console.log("HTTPS Server listening on port 1001"));
app.use(express.static(path.join(__dirname, "public")));

const dbConnection = mongoose.createConnection("mongodb://server:supersecuremongodbpassword@127.0.0.1:27017/hazelnut_db?authSource=admin");
const wss = new WebSocketServer({ port: 1002, maxPayload: 10 * 1024 });
const User = dbConnection.model("User", UserScheme, "hazelnut_userdb");

wss.on("connection", (client) => {
    client.sessionKey = null;
    client.userId     = null;

    client.ready      = false;
    client.alive      = true;

    client.on("message", async (event) => {
        try {
            const _data = JSON.parse(event.toString());

            const kyberHandler        = new KyberHandler(client, _data, process.env.ID);
            const pingHandler         = new PingHandler(client);
            const encryptedMsgHandler = new EncryptedMessageHandler(client, _data, SECRET_KEY);

            switch (_data.type) {
                case "key_exchange": kyberHandler.handleKyber();            break;
                case "ping":         pingHandler.handlePing();              break;
                case "enc":          encryptedMsgHandler.handleEncrypted(); break;
            }

        } catch (err) {
            console.log(err.toString());
        }
    });

    client.on("close", () => {
        console.log("closed connection");
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

setInterval(() => {
  wss.clients.forEach(async (client) => {
    if (!client.isAlive && client.ready) {
        await User.updateOne(
          { userId: client.userId },
          { $set: { online: false, lastSeen: new Date().toISOString() } }
        );

        console.log("terminating dead connection:", client.userId ?? "unknown");
        return client.terminate();
    }

    client.isAlive = false;
    client.send(JSON.stringify({ type: 'ping' }));
  });
}, 15000);