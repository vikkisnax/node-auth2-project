const bcrypt = require('bcryptjs'); // npm i bcryptjs
const jwt = require('jsonwebtoken'); 

const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const User = require('../users/users-model')

const { BCRPYT_ROUNDS, JWT_SECRET } = require("../secrets"); // use this secret! and add info to file

//write mw for validateRoleName then do this endpoint
router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

  const { username, password } = req.body
  const { role_name } = req

  // bcrypting the password before saving
  const hash = bcrypt.hashSync(password, BCRPYT_ROUNDS)
 // never save the plain text password in the db
 // username.password = hash // or do password:hash below

  User.add({ username, password:hash, role_name })
    .then( newUser => {
      res.status(201).json(newUser)
    })
    .catch(next) // same as .catch(err=>{next(err)})
});


//write CUE mw first and require jwt
router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  
  //compare password that user inputs to password in db
  if(bcrypt.compareSync(req.body.password, req.user.password)){
    //if credentials match/passwords are legit, we create token and send back to user
    const token = buildToken(req.user)
    res.json({
      status:200,
      message: `${req.user.username} is back`,
      token
    })
  } else {
    next({
      status: 401,
      message: "invalid credentials"
    })
  }
  
  //helper function for token that takes user info from db.
  // we can access user_id, etc bc of findBy code in users model 
  function buildToken(user){
    const payload = {
      //token will have these \/ 'claims' that it'll include
      subject: user.user_id,
      role_name: user.role_name,
      username: user.username
    }
    //we need options \/ for expiration
    const options = {
      expiresIn: '1d',
    }
    return jwt.sign(payload, JWT_SECRET, options)
  }
});

module.exports = router;
