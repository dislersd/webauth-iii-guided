const router = require("express").Router();
const bcrypt = require("bcryptjs");
// STEP 3 yarn add and rquire jsonwebtoken library
const jwt = require("jsonwebtoken");

const Users = require("../users/users-model.js");

// for endpoints beginning with /api/auth
router.post("/register", (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post("/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // STEP 1 - define token
        const token = generateToken(user);
        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token // STEP 4 - give token as response
        });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// STEP 2 - token generator function
function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  };
  const secret = "keep it secret, keep it safe";
  const options = {
    expiresIn: "1d"
  };
  return jwt.sign(payload, secret, options);
}

module.exports = router;
