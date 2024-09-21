# Secure Software Development Validation

## Overview

This repository contains a series of projects and examples designed to validate security in software development. The goal is to explore common vulnerabilities, like Cross-Site Scripting (XSS), and experiment with approaches to secure software applications. We focus on web-based APIs, authentication mechanisms (e.g., JWT), and input validation techniques.

By showcasing intentional vulnerabilities in controlled environments, developers can gain hands-on experience with exploiting and mitigating security issues in web applications.

## Project Structure

- **FastAPI JWT Authentication with XSS vulnerability**  
  Demonstrates how improper input handling can lead to XSS vulnerabilities in an API while using JWT-based authentication. The project simulates a user login system and exposes a vulnerable endpoint that allows XSS injection.

- **XSS Testing with Python Requests**  
  Includes an example of how a client application, written in Python, can interact with a web API and inject malicious scripts to demonstrate the impact of XSS attacks.

- **Token-Based Authentication**  
  This project simulates a secure token-based authentication system using JWT. However, it is also designed to highlight common pitfalls in authentication implementation, such as improper token handling or validation.

Each project is meant to be a sandbox environment where you can safely explore, test, and understand the consequences of common security flaws.

## Goals

- **Understand Security Vulnerabilities**:  
  Learn how common vulnerabilities like Cross-Site Scripting (XSS), SQL injection, and improper authentication can compromise applications.
  
- **Test and Validate Security Mechanisms**:  
  Experiment with code that has intentional security flaws and then work to secure it. You'll test different methods for mitigating security risks, such as input sanitization and proper authentication token management.

- **Best Practices for Secure Software Development**:  
  Get familiar with best practices for developing secure applications by fixing vulnerabilities and applying recommended security measures.

## Running the Project Locally

### Prerequisites

Ensure you have the following installed:

- [Python 3.9+](https://www.python.org/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Uvicorn](https://www.uvicorn.org/)
- [Python JWT Library (`python-jose`)](https://pypi.org/project/python-jose/)
  
You can install the required Python dependencies by running:

```sh
pip install -r requirements.txt
```
### Testing XSS Vulnerabilities
For example, you can use a simple curl command to test for XSS vulnerability:

```
curl -X GET "http://localhost:8000/profile?username=<script>alert('XSS Attack');</script>" -H "Authorization: Bearer <your_jwt_token>" -H "Accept: text/html"
```
Alternatively, you can open a browser and enter the URL:

```
http://localhost:8000/profile?username=<script>alert('XSS Attack');</script>
```

### JWT Authentication
Request a token via the /token endpoint by providing valid user credentials.

Example request:

```
curl -X POST "http://localhost:8000/token" -H "Content-Type: application/json" -d '{"username": "testuser", "password": "password"}'
```

Example response:

```
{
  "access_token": "your_token_here",
  "token_type": "bearer"
}
```

Use the token in subsequent requests to access protected resources (e.g., /profile).

# Security Considerations
These projects are intentionally vulnerable and should not be deployed in a production environment. They are designed solely for educational purposes to demonstrate potential security flaws and how they can be exploited.

Remember: After testing, always implement security best practices such as:

* Sanitizing all user inputs.
* Validating authentication tokens.
* Protecting against CSRF, XSS, and SQL injection attacks.
* Using proper encryption for sensitive data.

## Contributing
We welcome contributions aimed at improving security practices or demonstrating additional security vulnerabilities.

To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

## License
This project is licensed under the GNU License. See the LICENSE file for more details.

### Disclaimer: 
This repository and its code are for educational purposes only. Do not use it in production environments. The authors are not responsible for any misuse of the code or any consequences of exploiting the security flaws demonstrated here.

### Pontos Chave:
- A estrutura do README cobre a visão geral do projeto e seus objetivos.
- Instruções para rodar e testar os projetos localmente, com ênfase na demonstração de vulnerabilidades como XSS.
- Foco em práticas recomendadas de segurança e como elas podem ser aplicadas após os testes.

Se precisar de mais algum ajuste ou foco específico, é só avisar!