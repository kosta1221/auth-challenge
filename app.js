require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();

morgan.token("reqbody", (req) => {
	const newObject = {};
	for (const key in req.body) {
		if (JSON.stringify(req.body[key]).length > 100) {
			newObject[key] = "Too many to print...";
			continue;
		}
		newObject[key] = req.body[key];
	}
	return JSON.stringify(newObject);
});

app.use(express.json());
app.use(morgan(":method :url :status :res[content-length] - :response-time ms :reqbody"));

// normally store those in db
const users = [];
let refreshTokens = [];

app.get("/users", authorization, (req, res, next) => {
	res.json(users);
});

app.delete("/logout", (req, res) => {
	refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
	res.sendStatus(204);
});

app.post("/token", (req, res, next) => {
	const refreshToken = req.body.token;
	console.log(refreshTokens);
	console.log("token:", refreshToken);

	if (refreshTokens == null) return res.sendStatus(401);
	if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

	jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
		if (err) {
			return res.sendStatus(403);
		}

		const accessToken = generateAccessToken({ name: user.name });
		res.json({ accessToken: accessToken });
	});
});

app.post("/users/register", async (req, res, next) => {
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10);

		console.log(hashedPassword);

		const user = { name: req.body.name, password: hashedPassword };
		users.push(user);
		res.status(201).send();
	} catch (error) {
		next(error);
	}
});

app.post("/users/login", async (req, res, next) => {
	const user = users.find((user) => user.name === req.body.name);
	if (user == null) {
		return res.status(400).send("Cannot find user");
	}
	try {
		if (await bcrypt.compare(req.body.password, user.password)) {
			const accessToken = generateAccessToken(user);

			const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
			refreshTokens.push(refreshToken);

			res.json({ accessToken: accessToken, refreshToken: refreshToken });
		} else {
			res.status(401).send("not allowed");
		}
	} catch (error) {
		res.status(500).send();
	}
});

function authorization(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
		if (err) return res.sendStatus(403);

		req.user = user;
		next();
	});
}

function generateAccessToken(user) {
	return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15s" });
}

const errorHandler = (error, req, res, next) => {
	console.error(error);
	console.error(error.message);

	next(error);
};

app.use(errorHandler);

module.exports = app;
