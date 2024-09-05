const JWT = require("jsonwebtoken");
const generateToken = async (email) => {
  return JWT.sign({ email: email }, "your_secret_key", {
    expiresIn: "1m",
  });
};
const generateRefreshToken = async (email) => {
  return JWT.sign({ email: email }, "your_secret_key", {
    expiresIn: "30m",
  });
};
const saveCookies = async (res, cookieName, cookieValue, options) => {
  res.cookie(cookieName, cookieValue, options);
};

module.exports = {
  generateToken,
  generateRefreshToken,
  saveCookies,
};
