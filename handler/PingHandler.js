class PingHandler {
    constructor(client) {
        this.client = client;
    }

    handlePing() {
        this.client.send(JSON.stringify({ type: "pong" }));
        this.client.isAlive = true;
    }
}