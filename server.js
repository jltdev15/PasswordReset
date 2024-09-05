require("express-async-errors");
require("dotenv").config({ path: ".env" });
const mongoose = require("mongoose");
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require("morgan");
const connection = require("./db");
const cors = require("cors");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const port = 8080;

(async function db() {
  await connection();
})();

app.use(
  cors({
    credentials: true,
    origin: [
      "http://localhost:3000",
      "http://localhost:8080",
      "http://localhost:5173",
    ],
  })
);
app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(passport.initialize());

app.use("/api/v1", require("./routes/index.routes"));
app.use((error, req, res, next) => {
  res.status(500).json({
    error: error.message,
  });
});
app.listen(port, () => {
  console.log("Server is running in Port " + port);
});

module.exports = app;
