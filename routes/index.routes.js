const express = require("express");
const router = express.Router();
const {
  signUpController,
  resetPasswordRequestController,
  resetPasswordController,
  loginController,
  authUser,
  logoutController,
} = require("../controllers/auth.controller");

router.get("/auth/authUser", authUser);
router.post("/auth/signup", signUpController);
router.post("/auth/login", loginController);
router.post("/auth/logout", logoutController);
router.post("/auth/requestResetPassword", resetPasswordRequestController);
router.post("/auth/resetPassword", resetPasswordController);
module.exports = router;
