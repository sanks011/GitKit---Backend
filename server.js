import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { initializeApp, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import githubRoutes from './routes/github.js';
import repositoryRoutes from './routes/repository.js';

dotenv.config();

// Initialize Firebase Admin
const privateKey = process.env.FIREBASE_PRIVATE_KEY;
if (!privateKey) {
  throw new Error('FIREBASE_PRIVATE_KEY is not set in environment variables');
}

initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: privateKey.replace(/\\n/g, '\n')
  })
});

const app = express();

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? 'https://gitkitpro.web.app'
    : ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-GitHub-Token'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 600 // Cache preflight requests for 10 minutes
}));

// Handle preflight requests
app.options('*', cors());

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: true, // Don't count successful requests against the limit
  keyGenerator: (req) => {
    // Use the user's ID if available, otherwise use IP
    return req.user?.uid || req.ip;
  }
});

// Apply rate limiting to all routes
app.use(limiter);

app.use(express.json());

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      console.error('No authorization header provided');
      return res.status(401).json({ 
        error: 'Authentication required',
        details: 'No authorization header provided'
      });
    }

    // Extract token, handling both formats
    let token;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.split('Bearer ')[1];
    } else {
      token = authHeader;
    }

    if (!token) {
      console.error('No token found in authorization header');
      return res.status(401).json({ 
        error: 'Authentication required',
        details: 'No token found in authorization header'
      });
    }

    try {
      const decodedToken = await getAuth().verifyIdToken(token);
      req.user = decodedToken;
      next();
    } catch (error) {
      console.error('Firebase token verification error:', {
        code: error.code,
        message: error.message,
        stack: error.stack
      });
      return res.status(401).json({ 
        error: 'Invalid token',
        details: error.message
      });
    }
  } catch (error) {
    console.error('Authentication error:', {
      code: error.code,
      message: error.message,
      stack: error.stack
    });
    return res.status(401).json({ 
      error: 'Authentication failed',
      details: error.message
    });
  }
};

// Routes
app.use('/api/github', authenticateUser, githubRoutes);
app.use('/api/repository', authenticateUser, repositoryRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
}); 