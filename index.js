// DEPENDENCIES
const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();
const cors = require("cors");
require("dotenv").config();
// Secrets
const PORT = process.env.DEMO2_ORT || 4001;
const JWT_SECRET = process.env.DEMO2_JWT_SECRET;
const SERVER = process.env.DEMO2_SERVER || "http://localhost:4001";
const DATA_FILE_PATH = process.env.DEMO2_DATA_FILE_PATH || "./usersData.json";
const API_PATH = process.env.DEMO2_API_PATH || "./index.js";

// Configuration to convert JSON payloads to JS objects
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// CORS options configuration
const corsOptions = {
    origin: ["*"],
    credentials: true,
    optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
// Error handling
const errorHandler = async (error, req, res, next) => {
    const statusCode = error.status || 500;
    const errorMessage = error.message || "An unexpected error has occurred.";
    console.error(JSON.stringify({ name: error.name, message: error.message, stack: error.stack, cause: error.cause, code: error.code, path: error.path, errno: error.errno, type: error.type }, null, 2));
    if (res) {
        res.status(statusCode).send({ error: errorMessage });
    }
};
// Swagger Settings
const swaggerJsDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const swaggerOptions = {
    swaggerDefinition: {
        openapi: "3.0.0",
        info: {
            title: "Monolithic Express.js User Authentication and Authorization API",
            version: "1.0.1",
            description: "API documentation for a simple Express application that allows user registration, authentication and authorization.",
        },
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                },
            },
        },
        servers: [
            {
                url: `${SERVER}`,
            },
        ],
    },
    apis: [API_PATH],
};
const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));
// Data Storage Functions
const loadUsers = () => {
    try {
        const data = fs.readFileSync(DATA_FILE_PATH);
        return JSON.parse(data);
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error);
    }
};
// Initialize in-memory storage
const users = loadUsers();
const saveUsers = () => {
    try {
        fs.writeFileSync("./usersData.json", JSON.stringify(users, null, 2));
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error);
    }
};
// Authentication Middlewares
const checkValidUser = (decodedToken) => {
    try {
        let { id } = decodedToken;
        const foundUser = users.find((user) => user.id === id);
        return foundUser;
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
};
const decodeToken = async (req, res, next) => {
    try {
        let token = req.headers.authorization;
        if (typeof token !== "string" || token.length < 8) {
            console.log("No Token Found. Authentication Failed.");
            next();
            return;
        }
        token = token.slice(7, token.length);
        jwt.verify(token, JWT_SECRET, async function (err, decodedToken) {
            if (err) {
                console.log("Token Verification Failed. Authentication Failed.");
                next();
            } else {
                let isValidUser = checkValidUser(decodedToken);
                if (isValidUser) {
                    console.log("Token Verification Successful. User Verification Successful.");
                    req.user = decodedToken;
                    next();
                } else {
                    console.log("Token Verification Successful. User Verification Failed.");
                    next();
                }
            }
        });
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
};
/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *       description: "Enter your Bearer token in the format **&lt;token&gt;**"
 */
// Authorization Middlewares
const validateNotLoggedIn = (req, res, next) => {
    try {
        if (req.user) {
            console.log("Already logged in. User Authorization Failed.");
            return res.status(403).send({ success: false, message: "You do not have permission to access this resource." });
        }
        next();
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
};
const validateAdmin = (req, res, next) => {
    try {
        if (!req.user) {
            console.log("Authentication Failed.");
            return res.status(401).send({ success: false, message: "Authentication Failed. Please provide valid credentials." });
        }
        if (req.user.role !== "admin") {
            console.log("Admin access required.");
            return res.status(403).send({ success: false, message: "You do not have permission to access this resource." });
        }
        next();
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
};
const validateNotAdmin = (req, res, next) => {
    try {
        if (!req.user) {
            console.log("Authentication Failed.");
            return res.status(401).send({ success: false, message: "Authentication Failed. Please provide valid credentials." });
        }
        if (req.user.role === "admin") {
            console.log("Admins cannot perform this action.");
            return res.status(403).send({ success: false, message: "You do not have permission to access this resource." });
        }
        next();
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
};
// Routes
/**
 * @swagger
 * /users/register:
 *   post:
 *     summary: Register a new user account
 *     description: Register a user with a unique username and a strong password. The request must either not contain a Bearer token, contain an unverifiable token, or contain a verifiable token that doesn't reference an existing user.
 *     tags:
 *       - Users
 *     operationId: registerUser
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: "A unique username (3-15 characters). Must start with a letter and contain only letters, digits, and symbols ._-"
 *                 example: "U_ser-nam.e"
 *                 pattern: "^[a-zA-Z][\\w.-]{2,14}$"
 *               password:
 *                 type: string
 *                 description: "A password (8-32 characters) containing at least 1 uppercase, 1 lowercase, 1 digit, and 1 special character."
 *                 example: "p@55w0rD"
 *                 pattern: "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[~!@#$%^&*()_+\\-={[}\\]|\\\\:;\"'<,>.?\\/])[\\w~!@#$%^&*()+\\-={[}\\]|\\\\:;\"'<,>.?\\/]{8,32}$"
 *     responses:
 *       201:
 *         description: User registered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Registered Successfully."
 *       403:
 *         description: User is already authenticated via Bearer token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       500:
 *         description: Unexpected server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Something went wrong. Please try again later."
 *     security: [{ bearerAuth: [] }]
 *     deprecated: false
 */
app.post("/users/register", decodeToken, validateNotLoggedIn, async (req, res) => {
    try {
        const { username, password } = req.body;
        let newUser = {
            username: username,
            password: bcrypt.hashSync(password, 10),
            role: "user",
        };
        const savedUser = { ...newUser };
        users.push(savedUser);
        saveUsers();
        delete newUser.password;
        console.log("Registered Successfully");
        res.status(201).send({ success: true, message: "Registered Successfully", user: newUser });
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
});
/**
 * @swagger
 * /users/login:
 *   post:
 *     summary: Login to an existing user account
 *     description: Allows a user to log in by providing a valid username and password. The request must either not contain a Bearer token, contain an unverifiable token, or contain a verifiable token that doesn't reference an existing user.
 *     tags:
 *       - Users
 *     operationId: loginUser
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: "A valid username that exists in the database."
 *               password:
 *                 type: string
 *                 description: "The password that matches the provided username."
 *           examples:
 *             example1:
 *               summary: "An example of a login request for an existing non-admin user in the database."
 *               value:
 *                 username: "U_ser-nam.e"
 *                 password: "p@55w0rD"
 *             example2:
 *               summary: "An example of a login request for an existing admin user in the database."
 *               value:
 *                 username: "admin"
 *                 password: "p@55w0rD"
 *     responses:
 *       200:
 *         description: User logged in successfully. The response body property 'access' provide the authenticated user their respective Bearer Token which they can use for subsequent requests.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Logged in Successfully."
 *                 access:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR..."
 *       400:
 *         description: Invalid input format.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Invalid input format."
 *       401:
 *         description: Username does not exist or password does not match.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Invalid username or password."
 *       403:
 *         description: User is already authenticated via Bearer token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       500:
 *         description: Unexpected server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Something went wrong. Please try again later."
 *     security: [{ bearerAuth: [] }]
 *     deprecated: false
 */
app.post("/users/login", decodeToken, validateNotLoggedIn, (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.find((user) => user.username === username);
        if (!user || !bcrypt.compareSync(password, user.password)) {
            console.log("Invalid credentials.");
            return res.status(401).json({ success: false, message: "Access denied. Please provide valid credentials." });
        }
        let tempUser = { ...user };
        delete tempUser.password;
        const token = jwt.sign(tempUser, JWT_SECRET);
        console.log("User access granted.");
        return res.status(200).send({ success: true, message: "User access granted.", access: token });
    } catch (error) {
        console.error("Passed to error handler.");
        errorHandler(error, req, res);
    }
});
/**
 * @swagger
 * /users/visitors:
 *   get:
 *     summary: Confirm visitor status
 *     description: This endpoint returns a welcome message confirming the visitor status. The request must either not contain a Bearer token, contain an unverifiable token, or contain a verifiable token that doesn't reference an existing user.
 *     tags:
 *       - Visitors
 *     operationId: getVisitorStatus
 *     requestBody:
 *       required: false
 *     responses:
 *       200:
 *         description: Visitor confirmation successful.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Hello, welcome to the visitors page!"
 *       403:
 *         description: Authenticated users are not allowed to access the visitor endpoint.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       500:
 *         description: Unexpected server error occurred.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Something went wrong. Please try again later."
 *     security: [{ bearerAuth: [] }]
 *     deprecated: false
 */
app.get("/users/visitors", decodeToken, validateNotLoggedIn, (req, res) => {
    res.status(200).send({ success: true, message: `Hello, welcome to the visitors page!` });
});
/**
 * @swagger
 * /users/non-admins:
 *   get:
 *     summary: Confirm authenticated non-admin user status
 *     description: This endpoint returns a message confirming the authenticated non-admin user status. A valid Bearer token referencing an existing non-admin user must be provided.
 *     tags:
 *       - Users
 *     operationId: getNonAdminStatus
 *     requestBody:
 *       required: false
 *     responses:
 *       200:
 *         description: Non-admin user confirmation successful.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Hello <username>, welcome to the users page!"
 *       401:
 *         description: Unverifiable or missing Bearer token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Authentication failed. Please provide valid credentials."
 *       403:
 *         description: Access denied for admin users or inexistent user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       500:
 *         description: Unexpected server error occurred.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Something went wrong. Please try again later."
 *     security: [{ bearerAuth: [] }]
 *     deprecated: false
 */
app.get("/users/non-admins", decodeToken, validateNotAdmin, (req, res) => {
    res.status(200).send({ success: true, message: `Hello ${req.user.username}, welcome to the users page!` });
});
/**
 * @swagger
 * /users/admins:
 *   get:
 *     summary: Confirm authenticated admin user status
 *     description: This endpoint returns a message confirming the authenticated admin user status. A valid Bearer token referencing an existing admin user must be provided.
 *     tags:
 *       - Admins
 *     operationId: getAdminStatus
 *     requestBody:
 *       required: false
 *     responses:
 *       200:
 *         description: Admin user confirmation successful.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Hello <username>, welcome to the admin dashboard!"
 *       401:
 *         description: Unverifiable or missing Bearer token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Authentication failed. Please provide valid credentials."
 *       403:
 *         description: Access denied for non-admin users or inexistent user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "You do not have permission to access this resource."
 *       500:
 *         description: Unexpected server error occurred.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Something went wrong. Please try again later."
 *     security: [{ bearerAuth: [] }]
 *     deprecated: false
 */
app.get("/users/admins", decodeToken, validateAdmin, (req, res) => {
    res.status(200).send({ success: true, message: `Hello ${req.user.username}, welcome to the admin dashboard!` });
});
if (require.main === module) {
    app.listen(PORT || 4001, () => {
        console.log(`API is now online on port ${PORT || 4001}`);
    });
}
module.exports = app;
