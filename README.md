# Monolithic Express.js User Authentication and Authorization API

## Description

This is a code demonstration of a Monolithic API application built with Express.js, where users can register, authenticate, and verify authorization levels. It includes Swagger API documentation for easy route exploration.

## Deployment Disclaimer

The API currently deployed at: <https://simple-monolithic-user-api-demo.onrender.com>, runs on a free web service on Render.com. Web services running on the free tier spins down after 15 minutes of inactivity, which may delay API responses by 90seconds (or even timed out) while the service boots up from a cold start.

The Swagger UI documentation can be viewed and tested at: <https://simple-monolithic-user-api-demo.onrender.com/api-docs/>.

## Features

-   **Swagger API Documentation:** Provides documentation for each route directly accessible via the browser.
-   **Monolithic Code Structure:**
    -   All routes and server logic are defined in a single file (no separate route files or models).
    -   Uses core packages such as cors, dotenv, and express.
-   **User Data Handling:**
    -   User data is stored in a local file (managed using the fs module).
    -   No classes or models are used to define the data format.
-   **Registration and Authentication:**
    -   User passwords are encrypted using bcrypt before storing them.
    -   JWT (JSON Web Tokens) are generated upon login, provided as Bearer Tokens for subsequent requests.
-   **Authorization Middleware:**
    -   Demonstrates varied responses depending on the user role; different responses if user is, either: an unauthenticated user, an authenticated non-admin user, or an authenticated admin user.

## Sample Registered Credentials

Use these sample users to test the API:

-   **Admin User:**
    ```json
    { "username": "admin", "password": "p@55w0rD" }
    ```
-   **Non-admin User:**
    ```json
    { "username": "U_ser-nam.e", "password": "p@55w0rD" }
    ```

# How to Run

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/ronnmabunga/expressjs-fs-monolithic-user-api-demo.git
    cd expressjs-fs-monolithic-user-api-demo
    ```

2.  Install Dependencies:

    ```bash
    npm install
    ```

3.  Create a `.env` File:
    Define the environment variables (like the JWT secret) in the .env file. Example:

    ```env
    JWT_SECRET=your_jwt_secret
    PORT=your_port_number
    ```

4.  Run the Server:

    ```bash
    node index.js
    ```

5.  Access Swagger Documentation:

-   Visit `http://localhost:{PORT}/api-docs` in your browser to explore the API routes with Swagger UI.
    -   PORT - Port number indicated in the environment variables.

## API Routes Overview

-   **POST /users/register:** Registers a new user.
-   **POST /users/login:** Authenticates a user and returns a JWT token.
-   **GET /users/admin:** Restricted to authenticated admin users.
-   **GET /users/non-admin:** Restricted to authenticated non-admin users.
-   **GET /users/visitors:** Restricted to unauthenticated users.

## Dependencies

    express: Web framework for Node.js
    cors: Enables Cross-Origin Resource Sharing
    dotenv: Loads environment variables from .env
    fs: File system module to handle data storage
    bcrypt: Encrypts user passwords
    jsonwebtoken: Generates and verifies JWT tokens

## Dev Dependencies

    swagger-jsdoc: Generates Swagger documentation from JSDoc comments
    swagger-ui-express: Serves Swagger documentation via a web interface

# License

    This project is licensed under the GNU GENERAL PUBLIC LICENSE.
