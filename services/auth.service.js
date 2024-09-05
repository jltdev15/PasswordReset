const JWT = require("jsonwebtoken");
const User = require("../models/User.model");
const Token = require("../models/Token.model");
const sendEmail = require("../utils/email/sendEmail");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const JWTSecret = process.env.JWT_SECRET;
const bcryptSalt = process.env.BCRYPT_SALT;
const clientURL = process.env.CLIENT_URL;
const {
  generateToken,
  generateRefreshToken,
  saveCookies,
} = require("../helpers/helpers");

const login = async (res, email, password) => {
  const user = await User.findOne({ email: email });
  if (!user) {
    throw new Error("Account does not exist");
  }
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    throw new Error("Password does not match");
  }
  const accessToken = await generateToken(email);
  const refreshToken = await generateRefreshToken(email);
  await saveCookies(res, "accessToken", accessToken, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });
  await saveCookies(res, "refreshToken", refreshToken, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });

  return "Login Success!!!";
};
const logout = async (res) => {
  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });
  res.status(204).json({
    status: "Success!",
  });
};
const verifyToken = async (req, res, next) => {
  const accessToken = await req.cookies["accessToken"];
  const refreshToken = await req.cookies["refreshToken"];
  if (!accessToken) {
    return res.status(401).send("Access token not provided");
  }
  JWT.verify(accessToken, "your_secret_key", (err, user) => {
    if (!err) {
      req.user = user;
      console.log(req.user.email);
      return res.status(200).json({
        status: "Success",
        content: req.user,
      });
    }
    if (!refreshToken) {
      return res.status(401).send("Refresh token not provided");
    }
    JWT.verify(refreshToken, "your_secret_key", async (err, user) => {
      if (!err) {
        req.user = user;
        console.log(req.user.email);
        const newAccessToken = await generateToken(req.user.email);
        res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
        });
        return res.status(200).json({
          status: "Success",
          newToken: newAccessToken,
        });
      }
      return res.status(403).send("Invalid refresh token");
    });
  });
};
const signup = async (data) => {
  let user = await User.findOne({ email: data.email });
  if (user) {
    throw new Error("Email already exist", 422);
  }
  user = new User(data);
  const token = JWT.sign({ id: user._id }, JWTSecret);
  await user.save();

  return (data = {
    userId: user._id,
    email: user.email,
    name: user.name,
    token: token,
  });
};

const requestPasswordReset = async (email) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error("Email does not exist. Please try again");

  let token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  let resetToken = crypto.randomBytes(32).toString("hex");
  const hash = await bcrypt.hash(resetToken, Number(bcryptSalt));

  await new Token({
    userId: user._id,
    token: hash,
    createdAt: Date.now(),
  }).save();

  const link = `${clientURL}/passwordReset?token=${resetToken}&id=${user._id}`;

  sendEmail(
    user.email,
    "Password Reset Request",
    {
      name: user.name,
      link: link,
    },
    "./template/requestResetPassword.handlebars"
  );
  return { link };
};
const resetPassword = async (userId, token, password) => {
  let passwordResetToken = await Token.findOne({ userId });

  if (!passwordResetToken) {
    throw new Error("Invalid or expired password reset token");
  }

  console.log(passwordResetToken.token, token);

  const isValid = await bcrypt.compare(token, passwordResetToken.token);

  if (!isValid) {
    throw new Error("Invalid or expired password reset token");
  }

  const hash = await bcrypt.hash(password, Number(bcryptSalt));

  await User.updateOne(
    { _id: userId },
    { $set: { password: hash } },
    { new: true }
  );

  const user = await User.findById({ _id: userId });

  sendEmail(
    user.email,
    "Password Reset Successfully",
    {
      name: user.name,
    },
    "./template/resetPassword.handlebars"
  );

  await passwordResetToken.deleteOne();

  return { message: "Password reset was successful" };
};

module.exports = {
  signup,
  requestPasswordReset,
  resetPassword,
  login,
  verifyToken,
  logout,
};
