# Image Moderation FastAPI

A secure REST API with FastAPI that detects and blocks harmful, illegal, or otherwise unwanted imagery using AWS Rekognition service.

## Features

- **Image Content Moderation**: Automatically detect inappropriate content in uploaded images
- **JWT Authentication**: Secure token-based authentication system
- **Role-based Access Control**: Admin and user roles with different permissions
- **Usage Tracking**: Monitor API usage per token
- **Docker Support**: Fully containerized application

## Tech Stack

- **Backend**: Python 3.11 + FastAPI
- **Database**: MongoDB
- **Authentication**: JWT tokens
- **Image Processing**: AWS Rekognition
- **Containerization**: Docker + Docker Compose
- **Frontend**: HTML/CSS/JavaScript
- **Reverse Proxy**: Nginx

## Quick Start

### Prerequisites

- Docker & Docker Compose
- AWS Account with Rekognition access
- Git

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd image-moderation-solution
```

### 2. Environment Setup

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your actual values
nano .env
```

Required environment variables:
```bash
# MongoDB Configuration
MONGO_URI=mongodb://admin:admin123@mongodb:27017/image_moderation_db?authSource=admin
MONGO_ROOT_USERNAME=admin
MONGO_ROOT_PASSWORD=admin123

# JWT Configuration (Change this in production!)
JWT_SECRET=secret-key

# Admin Credentials
ADMIN_USER=admin
ADMIN_PASS=admin123

# AWS Rekognition Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1
```

### 3. Build and Run

```bash
# Build and start all services in background
docker-compose up --build -d
# To check if conatianers running
docker-compose ps
```

### 4. Access the Application

- **Frontend UI**: http://localhost
- **API Documentation**: http://localhost:7000/docs
- **Health Check**: http://localhost:7000/health
- **Admin Page**: http://localhost:7000/ui/admin.html
- **User Page**: http://localhost:7000/ui/user.html

## API Endpoints

### Authentication (Admin Only)
- `POST /auth/login` - Admin login
- `POST /auth/tokens` - Create new tokens
- `GET /auth/tokens` - List all tokens
- `DELETE /auth/tokens/{token}` - Delete a token
- `POST /auth/verify` - Verify token validity

### Image Moderation
- `POST /moderate` - Upload and moderate an image

### System
- `GET /health` - Health check endpoint

## Usage Guide adn Flow

### 1. Admin Login
1. Navigate to http://localhost
2. Use the admin credentials from your `.env` file
3. Click "Log In" to receive an admin JWT token

### 2. Create User Tokens
1. After admin login, use the token management section
2. Click "Create User Token" or "Create Admin Token"
3. Copy the generated token for API access

### 3. Moderate Images
1. Switch to the user interface or use the admin interface
2. Enter a valid token in the token field
3. Upload an image file
4. Click "Moderate" to analyze the image
5. View the safety report with confidence scores

### 4. API Usage
```bash
# Example: Moderate an image via API
curl -X POST "http://localhost:7000/moderate" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@/path/to/your/image.jpg"
```

## Development

### Local Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install flake8 black isort mypy pytest

# Run the application
uvicorn main:app --reload --port 7000
```

### GitHub Branch Protection Rules
- All changes to `main` require a Pull Request
- PRs require at least one code review
- All CI checks must pass before merging



### Health Checks
The application includes comprehensive health checks:
- API server status
- Database connectivity
- Service health endpoints

### Docker Running Logs

# Backend logs
docker-compose logs -f backend

# Database logs
docker-compose logs -f mongodb

# All services
docker-compose logs -f

# Database Access

```bash
# Connect to MongoDB container
docker exec -it image-moderation-mongodb mongosh

# Using authentication
mongosh "mongodb://admin:admin123@localhost:27017/image_moderation_db?authSource=admin"
```

### Common Issues

1. **Port conflicts**: Change ports in `docker-compose.yml` if needed
2. **MongoDB connection**: Ensure MongoDB container is running
3. **AWS credentials**: Verify AWS access key and secret key
