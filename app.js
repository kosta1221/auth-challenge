/* write your server code here */
const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
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

app.post("/users/register", (req, res, next) => {});

module.exports = app;
