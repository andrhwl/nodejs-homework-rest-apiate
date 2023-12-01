const express = require("express");

const UsersController = require("../../controllers/users");
const auth = require("../../middleware/auth")
const router = express.Router();

const jsonParser = express.json();

router.post("/register", jsonParser, UsersController.register);
router.post("/login", jsonParser, UsersController.login);
router.post("/current", auth, jsonParser, UsersController.current);
router.post("/logout", auth, UsersController.logout);

module.exports = router;
