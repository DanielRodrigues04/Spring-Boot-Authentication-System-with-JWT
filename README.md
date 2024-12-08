# Authentication and Authorization System

A robust authentication and authorization system built with Spring Boot, implementing JWT (JSON Web Token) for secure authentication, role-based access control, and email verification.

## Features

- 🔐 User Authentication
  - Registration with email verification
  - Login with JWT token generation
  - Secure password encryption using BCrypt

- 👥 Role-Based Authorization
  - Support for multiple user roles (USER, ADMIN)
  - Role-based access control for endpoints
  - Method-level security

- 🔒 Security
  - JWT-based stateless authentication
  - Token validation and verification
  - Protection against common security vulnerabilities

- ✉️ Email Services
  - Email verification for new registrations
  - SMTP integration with Gmail

## Technology Stack

- **Spring Boot 3.1.5**: Core framework
- **Spring Security**: Authentication and authorization
- **Spring Data JPA**: Data persistence
- **H2 Database**: In-memory database
- **JSON Web Token (JWT)**: Secure token-based authentication
- **Java Mail Sender**: Email services
- **Lombok**: Reduce boilerplate code
- **Jakarta Validation**: Input validation

## Prerequisites

- JDK 17 or later
- Maven 3.6+ or later
- Gmail account (for email services)

## Configuration

### Application Properties

The application can be configured through `application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:authdb
    username: sa
    password: password
  mail:
    host: smtp.gmail.com
    port: 587
    username: ${MAIL_USERNAME}
    password: ${MAIL_PASSWORD}

app:
  jwt:
    secret: ${JWT_SECRET}
    expiration: 86400000  # 24 hours
```

### Environment Variables

Set up the following environment variables:
- `MAIL_USERNAME`: Your Gmail address
- `MAIL_PASSWORD`: Your Gmail app password
- `JWT_SECRET`: Secret key for JWT token generation

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/auth-system.git
cd auth-system
```

2. Set up environment variables:
```bash
export MAIL_USERNAME=your.email@gmail.com
export MAIL_PASSWORD=your-app-password
export JWT_SECRET=your-secret-key
```

3. Build the project:
```bash
mvn clean install
```

4. Run the application:
```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

## API Endpoints

### Authentication
- `POST /api/auth/signup`: Register new user
- `POST /api/auth/signin`: Authenticate user and get JWT
- `GET /api/auth/verify`: Verify email address

### Protected Resources
- `GET /api/test/user`: Access user content (requires USER role)
- `GET /api/test/admin`: Access admin content (requires ADMIN role)

## Security Configuration

The security configuration is managed through `WebSecurityConfig.java`:
- CSRF protection disabled for stateless JWT authentication
- Public endpoints for authentication
- Protected endpoints requiring authentication
- JWT token filter for request authentication
- BCrypt password encoding

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Spring Security Documentation
- JWT.io
- Spring Boot Documentation