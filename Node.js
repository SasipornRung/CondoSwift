{
  "name": "condoswift-backend",
  "version": "1.0.0",
  "description": "CondoSwift - Thai Condo Marketplace Backend API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "dotenv": "^16.3.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "express-rate-limit": "^6.10.0",
    "express-validator": "^7.0.1",
    "multer": "^1.4.5",
    "mongoose": "^7.5.0",
    "nodemailer": "^6.9.4",
    "uuid": "^9.0.0",
    "sharp": "^0.32.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.4",
    "supertest": "^6.3.3"
  },
  "keywords": [
    "real-estate",
    "condo",
    "marketplace",
    "thailand",
    "api"
  ],
  "author": "CondoSwift Team",
  "license": "MIT"
}
