const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const users = [];

// App configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/users", (req, res) => {
    res.json(users);
});

// Authorization
function verifyToken(req, res, next) {
    if (req.headers && req.headers.authorization && req.headers.authorization.split(' ')[0] === "JWT") {
        jwt.verify(req.headers.authorization.split(' ')[1], process.env.API_SECRET, (err, decode) => {
            if (err) res.locals.user = undefined;
            console.log(decode);
            let user = users.find(u => u.email === decode.id);
            if(user === undefined) {
                res.status(500).send("Error");
                return;
            }
            else res.locals.user = user;
            console.log(user);
            next();
        });
    } else {
        res.locals.user = undefined;
        next();
    }
}

// Authentication controller
app.post("/signup", (req, res) => {
    let user = {
        fullName: req.body.fullName,
        email: req.body.email,
        role: req.body.role,
        password: bcrypt.hashSync(req.body.password, 8)
    };

    users.push(user);
    res.status(201).send({ message: "User successfully registered" });
});

app.post("/signin", (req, res) => {
    let user = users.find(u => u.email === req.body.email);

    let passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

    if(!passwordIsValid) {
        res.status(401).send({ accessToken: null, message: "Invalid password" });
    }

    let token = jwt.sign({
        id: user.email
    }, process.env.API_SECRET, {
        expiresIn: 86400
    });

    res.status(200)
        .send({
            user: {
                email: user.email,
                fullName: user.fullName
            },
            message: "Login successful",
            accessToken: token
        });
});

app.get("/supersecretcontent", verifyToken, (req, res) => {
    if(res.user)
        res.status(403).send("Invalid JWT token");
    res.status(200).send("THIS IS TOP SECRET!");
});

app.get("/myprofile", (req, res) => {

});

const PORT = process.env.PORT || 3000;
app.listen(PORT);