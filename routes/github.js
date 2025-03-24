import express from 'express';
import { Octokit } from '@octokit/rest';
import OpenAI from 'openai';
import dotenv from 'dotenv';
import axios from 'axios';
import { getAuth } from 'firebase-admin/auth';

dotenv.config();

const router = express.Router();
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Middleware to check GitHub token
const checkGitHubToken = async (req, res, next) => {
  try {
    // Get GitHub token from headers
    const githubToken = req.headers['x-github-token'];
    if (!githubToken) {
      console.error('No GitHub token provided');
      return res.status(401).json({ 
        error: 'GitHub authentication required',
        details: 'No GitHub token found in headers'
      });
    }

    // Create Octokit instance with GitHub token
    req.octokit = new Octokit({ auth: githubToken });
    
    // Test the token by making a simple API call
    try {
      await req.octokit.users.getAuthenticated();
      next();
    } catch (error) {
      console.error('GitHub token validation error:', {
        code: error.code,
        message: error.message,
        stack: error.stack
      });
      return res.status(401).json({ 
        error: 'Invalid GitHub token',
        details: error.message
      });
    }
  } catch (error) {
    console.error('Token verification error:', {
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

// Check if user has connected GitHub
router.get('/check-connection', async (req, res) => {
  try {
    // Get user's GitHub token from your database
    // This is where you'd check if the user has connected their GitHub account
    const hasGitHubToken = false; // Replace with actual database check
    res.json({ connected: hasGitHubToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Handle GitHub OAuth callback
router.get('/callback', async (req, res) => {
  try {
    const { code } = req.query;

    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }, {
      headers: {
        Accept: 'application/json',
      },
    });

    const { access_token } = tokenResponse.data;

    // Here you would:
    // 1. Store the token in your database associated with the user
    // 2. Redirect the user back to your app

    res.redirect('/dashboard?github_connected=true');
  } catch (error) {
    console.error('GitHub OAuth Error:', error);
    res.redirect('/dashboard?error=github_auth_failed');
  }
});

// Get user profile
router.get('/profile', checkGitHubToken, async (req, res) => {
  try {
    const { data: profile } = await req.octokit.users.getAuthenticated();
    if (!profile) {
      throw new Error('Failed to fetch GitHub profile');
    }
    res.json(profile);
  } catch (error) {
    console.error('Error fetching GitHub profile:', error);
    res.status(500).json({ 
      error: 'Failed to fetch GitHub profile',
      details: error.message
    });
  }
});

// Get user repositories
router.get('/repositories', checkGitHubToken, async (req, res) => {
  try {
    const { data: repos } = await req.octokit.repos.listForAuthenticatedUser({
      sort: 'updated',
      per_page: 100
    });
    
    if (!Array.isArray(repos)) {
      throw new Error('Invalid repositories data received from GitHub');
    }
    
    res.json(repos);
  } catch (error) {
    console.error('Error fetching repositories:', error);
    res.status(500).json({ 
      error: 'Failed to fetch repositories',
      details: error.message
    });
  }
});

// Get repository details
router.get('/repositories/:owner/:repo', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const { data: repository } = await req.octokit.repos.get({
      owner,
      repo
    });
    res.json(repository);
  } catch (error) {
    console.error('Error fetching repository details:', error);
    res.status(500).json({ error: 'Failed to fetch repository details' });
  }
});

// Analyze repository
router.post('/analyze', async (req, res) => {
  try {
    const { repositoryData } = req.body;
    
    const prompt = `Analyze this GitHub repository and provide insights:
    Repository: ${repositoryData.name}
    Description: ${repositoryData.description || 'No description provided'}
    Language: ${repositoryData.language || 'Not specified'}
    Topics: ${repositoryData.topics?.join(', ') || 'None'}
    Stars: ${repositoryData.stargazers_count}
    Forks: ${repositoryData.forks_count}
    Open Issues: ${repositoryData.open_issues_count}
    
    Please provide a comprehensive analysis covering:
    1. Project overview and main purpose
    2. Technical stack and architecture assessment
    3. Code quality and maintainability indicators
    4. Community engagement and activity level
    5. Potential improvements and recommendations
    6. Notable features and unique selling points
    7. Development practices and patterns used
    8. Security considerations and best practices`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4-turbo-preview",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
      max_tokens: 1000
    });

    res.json({
      analysis: completion.choices[0].message.content
    });
  } catch (error) {
    console.error('Analysis Error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message
    });
  }
});

// Generate documentation
router.post('/generate-docs', async (req, res) => {
  try {
    const { repoData, docType } = req.body;

    let prompt = '';
    switch (docType) {
      case 'readme':
        prompt = `Generate a comprehensive README.md for this repository:
        Name: ${repoData.name}
        Description: ${repoData.description || 'No description provided'}
        Language: ${repoData.language || 'Not specified'}
        
        Include sections for:
        1. Project Overview
        2. Features
        3. Installation
        4. Usage
        5. Configuration
        6. Contributing
        7. License
        8. Contact Information`;
        break;

      case 'contributing':
        prompt = `Generate a CONTRIBUTING.md guide for this repository:
        Name: ${repoData.name}
        
        Include sections for:
        1. Code of Conduct
        2. Getting Started
        3. Development Setup
        4. Pull Request Process
        5. Coding Standards
        6. Testing Guidelines
        7. Documentation Requirements
        8. Review Process`;
        break;

      case 'codeOfConduct':
        prompt = `Generate a CODE_OF_CONDUCT.md for this repository:
        Name: ${repoData.name}
        
        Include sections for:
        1. Purpose and Scope
        2. Expected Behavior
        3. Unacceptable Behavior
        4. Responsibilities
        5. Enforcement
        6. Reporting Guidelines
        7. Resolution Process
        8. Attribution`;
        break;

      case 'api':
        prompt = `Generate API documentation for this repository:
        Name: ${repoData.name}
        Language: ${repoData.language || 'Not specified'}
        
        Include sections for:
        1. API Overview
        2. Authentication
        3. Endpoints
        4. Request/Response Formats
        5. Error Handling
        6. Rate Limiting
        7. Examples
        8. SDK Integration`;
        break;

      default:
        throw new Error('Invalid documentation type');
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4-turbo-preview",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
      max_tokens: 2000
    });

    res.json({
      documentation: completion.choices[0].message.content
    });
  } catch (error) {
    console.error('Documentation Generation Error:', error);
    res.status(500).json({
      error: 'Documentation generation failed',
      details: error.message
    });
  }
});

export default router; 