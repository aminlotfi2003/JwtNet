# JwtNet

JwtNet is a modular ASP.NET Core 8 Web API that demonstrates how to build a production-ready authentication and account management system using JSON Web Tokens (JWT). The project applies a Clean Architecture layout (Domain, Application, Infrastructure, and API layers) and showcases patterns such as CQRS with MediatR, FluentValidation, and ASP.NET Core Identity over Entity Framework Core.

## Features

### Authentication & Authorization
- **JWT access and refresh tokens** with configurable lifetimes and symmetric signing keys. Refresh tokens are stored hashed to keep secrets off-disk.
- **Secure user registration** flow that enforces unique email addresses, Identity password policies, and immediate issuance of a token pair.
- **Login with lockout support** that records failed attempts, supports optional two-factor flows, and revokes prior refresh tokens before issuing new ones.
- **Two-factor authentication via email** with endpoints to generate and validate email codes before unlocking the session.

### Account Lifecycle Management
- **Password rotation policy** that enforces a 90-day minimum interval, prevents re-use of the last five passwords, and re-issues fresh token pairs after a successful change.
- **Forgot password workflow** that issues reset tokens (logic encapsulated via Identity).
- **Refresh token rotation and logout** endpoints to maintain session hygiene.
- **Account activation & deactivation** APIs for administrative control.

### Auditing & Observability
- **Login history tracking** that records IP address, user agent, and timestamp for each successful sign-in, with an API to retrieve the latest entries.
- **Password history retention** to support the rotation policy and guard against reuse.

### API Experience
- **API versioning** using URL segments with default versioning behavior.
- **Swagger/OpenAPI documentation** pre-configured with JWT Bearer security definitions.
- **CORS policy** that allows development clients to reach the API from any origin.

## Technology Stack
- .NET 8, ASP.NET Core Web API
- Entity Framework Core & SQL Server
- ASP.NET Core Identity
- MediatR & CQRS pattern
- FluentValidation for request validation
- Swashbuckle for OpenAPI/Swagger
- Docker support for containerized deployments

## Solution Structure
```
src/
  API/               # ASP.NET Core entry point, controllers, Swagger & versioning
  Application/       # CQRS handlers, DTOs, abstractions, validation
  Domain/            # Entity definitions & enums
  Infrastructure/    # EF Core DbContext, repositories, services, DI wiring
```

## Getting Started

### Prerequisites
- [.NET SDK 8.0](https://dotnet.microsoft.com/download)
- SQL Server instance (local or remote)
- Optional: Docker Engine if you prefer containerized execution

### Clone and Restore
```bash
git clone <repository-url>
cd JwtNet
dotnet restore
```

### Configure Settings
1. Update the connection string and JWT settings in `src/API/appsettings.Development.json` (or via [user secrets](https://learn.microsoft.com/aspnet/core/security/app-secrets)):
   ```json
   {
     "ConnectionStrings": {
       "Default": "Server=localhost;Database=JwtNet;User Id=...;Password=...;TrustServerCertificate=True"
     },
     "Jwt": {
       "Issuer": "JwtNet",
       "Audience": "JwtNet",
       "SigningKey": "your-very-long-secret-key",
       "AccessTokenLifetimeMinutes": 15,
       "RefreshTokenLifetimeDays": 7
     }
   }
   ```
2. Ensure the JWT signing key is at least 128 bits and kept out of source control.

### Apply Database Migrations
Use the Entity Framework Core tooling to create the database schema:
```bash
dotnet ef database update \
  --project src/Infrastructure/Infrastructure.csproj \
  --startup-project src/API/API.csproj
```
This command builds the Infrastructure migrations (refresh tokens, password history, login history, Identity tables) and applies them to the configured database.

### Run the API Locally
```bash
dotnet run --project src/API/API.csproj
```
The API listens on the ports defined by ASP.NET Core (typically `https://localhost:7xxx` and `http://localhost:5xxx`). Swagger UI is automatically exposed in development at `/swagger` with JWT Bearer support.

### Run with Docker
Build and run a containerized image (requires Docker):
```bash
docker build -t jwt-net-api -f src/API/Dockerfile .
docker run --rm -p 8080:8080 -e ConnectionStrings__Default="..." -e Jwt__SigningKey="..." jwt-net-api
```
The published image uses the multi-stage Dockerfile to produce a lightweight runtime image.

## API Surface
| Method | Route | Description |
| ------ | ----- | ----------- |
| `POST` | `/api/v1/identity/register` | Create a new account and receive access/refresh tokens. |
| `POST` | `/api/v1/identity/login` | Authenticate with email and password; may request two-factor. |
| `POST` | `/api/v1/identity/login/two-factor` | Complete login with the emailed verification code. |
| `POST` | `/api/v1/identity/refresh` | Exchange a valid refresh token for a new token pair. |
| `POST` | `/api/v1/identity/logout` | Revoke the supplied refresh token. |
| `POST` | `/api/v1/identity/users/{id}/password/rotate` | Rotate password after 90 days and refresh tokens. |
| `POST` | `/api/v1/identity/forgot-password` | Request a password reset token. |
| `POST` | `/api/v1/identity/users/{id}/two-factor/email/generate` | Generate a two-factor email code. |
| `POST` | `/api/v1/identity/users/{id}/two-factor/email/enable` | Enable email-based two-factor authentication. |
| `GET`  | `/api/v1/identity/users/{id}/login-history?count=10` | Retrieve recent login activity. |
| `GET`  | `/api/v1/users` | List users, optionally including inactive records. |
| `GET`  | `/api/v1/users/{id}` | Fetch details for a specific user. |
| `POST` | `/api/v1/users/{id}/activate` | Activate a previously deactivated user. |
| `POST` | `/api/v1/users/{id}/deactivate` | Deactivate a user account. |

## Security Considerations
- Password complexity, lockout thresholds, and two-factor providers are configured through ASP.NET Core Identity.
- Refresh tokens are revoked on login, logout, and password change to reduce token replay risk.
- CORS defaults to permissive for local development; tighten the policy before production.

## Extending the Project
- Add additional two-factor providers (SMS, authenticator apps) by extending the command handlers.
- Integrate external email services by plugging into the Identity email sender.
- Introduce unit/integration tests using xUnit or NUnit against the Application layer handlers.
- Harden production settings (strict CORS, HTTPS enforcement, secrets management) before deploying.

## License
This project is licensed under the MIT License.
