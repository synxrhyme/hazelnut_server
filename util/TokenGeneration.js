const crypto = require("crypto");
const jwt    = require("jsonwebtoken");

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

function generateUserID(_fcmToken) {
    const number1 = getRandomInt(99);
    const number2 = getRandomInt(999);

    const fcmToken = _fcmToken.toString();

    return number1.toString() + fcmToken.substring(10, 15) + number2.toString();
}

function generateAuthToken(userId, secretKey) {
  return jwt.sign(
    { userId },
    secretKey,
    { expiresIn: "30m" }
  );
}

function generateRefreshToken() {
  return crypto.randomBytes(64).toString('hex');
}

module.exports = { generateUserID, generateAuthToken, generateRefreshToken };