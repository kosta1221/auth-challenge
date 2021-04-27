const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();

ACCESS_TOKEN_SECRET =
	"09a4b3c1b305c0d55e43f5afe5082c31babf05da8f9e87c0a941c4e6c334ec55c95194984caf70ad0cd8c7fac1fb0eafdfc8b8104dacd7833a3bc59a81c81ab6";
REFRESH_TOKEN_SECRET =
	"1436aa86daafcba5dc469bf1d42c2389e65778f15b29fdc5ff734a201c2af36d51d1b009341fb9f2fcb68cfd7a0c4f8a3ada63dc6b0486983ab42950eeb24060";

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
const users = [
	{
		email: "admin@email.com",
		name: "admin",
		password: bcrypt.hashSync("Rc123456!", 10),
		isAdmin: true,
	},
];
const information = [
	{
		email: "admin@email.com",
		info: "admin info",
	},
];
let refreshTokens = [];

app.get("/api/v1/information", (req, res, next) => {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
		if (err) return res.sendStatus(403);

		req.user = user;
		res.json([{ name: user.name, email: user.email }]);
	});
});

app.get("/api/v1/users", (req, res, next) => {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
		if (err) return res.sendStatus(403);

		if (!user.isAdmin) {
			return res.sendStatus(403);
		}

		res.json(users);
	});
});

app.post("/users/logout", (req, res) => {
	refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
	res.sendStatus(200);
});

app.post("/users/token", (req, res, next) => {
	const refreshToken = req.body.token;
	console.log(refreshTokens);
	console.log("token:", refreshToken);

	if (!refreshToken) return res.sendStatus(401);
	if (refreshTokens == null) return res.sendStatus(401);
	if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

	jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
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

		const user = {
			name: req.body.name,
			email: req.body.email,
			password: hashedPassword,
			isAdmin: false,
		};
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

			const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET);
			refreshTokens.push(refreshToken);
			let isAdmin = false;
			if (user.isAdmin) isAdmin = true;
			res.json({
				accessToken: accessToken,
				refreshToken: refreshToken,
				name: req.body.name,
				isAdmin,
			});
		} else {
			res.status(401).send("not allowed");
		}
	} catch (error) {
		res.status(500).send();
	}
});

app.post("/users/tokenValidate", authorization, (req, res) => {
	res.json({ valid: true });
});

app.options("/", (req, res) => {
	const options = [
		{
			method: "post",
			path: "/users/register",
			description: "Register, Required: email, name, password",
			example: { body: { email: "user@email.com", name: "user", password: "password" } },
		},
		{
			method: "post",
			path: "/users/login",
			description: "Login, Required: valid email and password",
			example: { body: { email: "user@email.com", password: "password" } },
		},
		{
			method: "post",
			path: "/users/token",
			description: "Renew access token, Required: valid refresh token",
			example: { headers: { token: "*Refresh Token*" } },
		},
		{
			method: "post",
			path: "/users/tokenValidate",
			description: "Access Token Validation, Required: valid access token",
			example: { headers: { Authorization: "Bearer *Access Token*" } },
		},
		{
			method: "get",
			path: "/api/v1/information",
			description: "Access user's information, Required: valid access token",
			example: { headers: { Authorization: "Bearer *Access Token*" } },
		},
		{
			method: "post",
			path: "/users/logout",
			description: "Logout, Required: access token",
			example: { body: { token: "*Refresh Token*" } },
		},
		{
			method: "get",
			path: "api/v1/users",
			description: "Get users DB, Required: Valid access token of admin user",
			example: { headers: { authorization: "Bearer *Access Token*" } },
		},
	];

	const authHeader = req.headers["authorization"];

	if (!authHeader) return res.json(options.slice(0, 2));

	const token = authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
		if (err) return res.json(options.slice(0, 3));

		if (!user.isAdmin) return res.json(options.slice(0, 6));

		return res.json(options);
	});
});

function generateAccessToken(user) {
	return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "10s" });
}

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

const errorHandler = (error, req, res, next) => {
	console.error(error);
	console.error(error.message);

	next(error);
};

app.use(errorHandler);

module.exports = app;
