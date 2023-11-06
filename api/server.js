const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

//require routers 
const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");

const server = express();

//helmet = a lot of mw's in one - plugging lots of security related mw. can be configured individually. check helmet doc for what's available
server.use(helmet());
server.use(express.json());
//cors = configurable. check doc
server.use(cors());

//plug in routers 
server.use("/api/auth", authRouter);
server.use("/api/users", usersRouter);

//error handling mw 
server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
