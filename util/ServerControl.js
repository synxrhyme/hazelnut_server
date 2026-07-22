const readline = require("readline");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "> ",
});

function safeLog(...args) {
    readline.cursorTo(process.stdout, 0);
    readline.clearLine(process.stdout, 0);
    console.log(...args);
    rl.prompt(true); // true = force redraw inkl. bereits getippter Eingabe
}

module.exports = { safeLog, rl };