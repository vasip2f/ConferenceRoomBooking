const express = require('express');
const { signup, login, verifyToken, getuser, refereshToken, logout,  } = require('../controller/user-controller');

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.get("/user",verifyToken,getuser);
router.get("/referesh", refereshToken, verifyToken, getuser);
router.post("/logout", verifyToken, logout );

//verify token


module.exports = router;

