const mongoose = require("mongoose");
require("dotenv").config({ path: ".env" });
const db = process.env.DB_URL;

module.exports = async function connection() {
  try {
    await mongoose
      .connect(db)
      .then(() => console.log("Connected to Database!"))
      .catch((err) => {
        console.log(err);
      });
  } catch (error) {
    console.log(error);
  }
};
