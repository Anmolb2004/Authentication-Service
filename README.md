# Serverless Authentication API on AWS

This project is a complete, deployable, and scalable serverless authentication service built on Amazon Web Services (AWS). It provides a secure RESTful API for user registration, login, and management using JWT-based authentication.

The entire cloud infrastructure is defined and managed using the AWS Cloud Development Kit (CDK), demonstrating a modern Infrastructure as Code (IaC) approach.

## Tech Stack

* **Backend:** Python 3.9, FastAPI
* **Database:** Amazon DynamoDB (NoSQL, Serverless)
* **Cloud Provider:** AWS
    * **Compute:** AWS Lambda
    * **API Layer:** Amazon API Gateway
    * **Secrets Management:** AWS Secrets Manager
* **Infrastructure as Code:** AWS CDK (TypeScript)
* **Deployment:** Docker (for bundling Lambda assets)

## Features

* **User Registration:** Create new users with hashed passwords (`bcrypt`).
* **User Login:** Authenticate users and issue secure JWT (JSON Web Tokens).
* **Protected Routes:** Endpoints to securely fetch or delete user data using a valid JWT.
* **Fully Serverless:** No servers to manage, scales automatically, and benefits from pay-per-use billing.
* **Automated Deployment:** The entire stack, from the database to the API logic, is deployed with a single command.

---

## Live Demo & Endpoints

The API is deployed and live.

* **Interactive Documentation (Swagger UI):** `https://gw2mi4khol.execute-api.us-west-2.amazonaws.com/prod/docs`

You can use the interactive docs to test all endpoints live in your browser.

