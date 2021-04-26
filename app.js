/* write your server code here */
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

const users = [];

app.get("/users", (req, res, next) => {
	res.json(users);
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
			res.send("success");
		} else {
			res.status(401).send("not allowed");
		}
	} catch (error) {
		res.status(500).send();
	}
});

const errorHandler = (error, req, res, next) => {
	console.error(error);
	console.error(error.message);

	next(error);
};

app.use(errorHandler);

module.exports = app;
