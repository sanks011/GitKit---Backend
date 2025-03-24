import express from 'express';
import { Octokit } from '@octokit/rest';
import OpenAI from 'openai';
import dotenv from 'dotenv';
import { getAuth } from 'firebase-admin/auth';

dotenv.config();

const router = express.Router();
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Middleware to check GitHub token
const checkGitHubToken = async (req, res, next) => {
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
    } catch (error) {
      console.error('Firebase token verification error:', {
        code: error.code,
        message: error.message,
        stack: error.stack
      });
      return res.status(401).json({ 
        error: 'Invalid Firebase token',
        details: error.message
      });
    }
    
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

const extractJSON = (content) => {
  try {
    // First try direct parse
    try {
      return JSON.parse(content);
    } catch (e) {
      console.log('Direct JSON parse failed:', e.message);
    }

    // Try to find JSON object boundaries
    const startIndex = content.indexOf('{');
    const endIndex = content.lastIndexOf('}');
    
    if (startIndex === -1 || endIndex === -1) {
      console.log('No JSON object boundaries found');
      return null;
    }

    // Extract content between first { and last }
    const jsonContent = content.substring(startIndex, endIndex + 1);
    
    try {
      return JSON.parse(jsonContent);
    } catch (e) {
      console.log('JSON parse after extraction failed:', e.message);
      return null;
    }
  } catch (error) {
    console.error('JSON extraction error:', error);
    return null;
  }
};

const validateAnalysis = (analysis) => {
  try {
    // Check if all required fields are present
    const requiredFields = [
      'technologies',
      'completion',
      'complexity',
      'codeQuality',
      'technicalDebt',
      'recommendations'
    ];

    for (const field of requiredFields) {
      if (!(field in analysis)) {
        console.log(`Missing required field: ${field}`);
        return false;
      }
    }

    // Validate field types
    if (!Array.isArray(analysis.technologies) ||
        typeof analysis.completion !== 'number' ||
        !['Low', 'Medium', 'High'].includes(analysis.complexity) ||
        !Array.isArray(analysis.codeQuality) ||
        !Array.isArray(analysis.technicalDebt) ||
        !Array.isArray(analysis.recommendations)) {
      console.log('Invalid field types in analysis');
      return false;
    }

    return true;
  } catch (error) {
    console.error('Analysis validation error:', error);
    return false;
  }
};

// Get repository analysis
router.get('/:owner/:repo/analysis', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;
    
    console.log('Starting repository analysis with params:', { owner, repo });
    
    // Validate input parameters
    if (!owner || !repo) {
      console.error('Missing required parameters:', { owner, repo });
      return res.status(400).json({
        error: 'Missing required parameters',
        details: 'Owner and repository name are required'
      });
    }

    // Validate GitHub token
    if (!req.octokit) {
      console.error('GitHub client not initialized');
      return res.status(500).json({
        error: 'GitHub client error',
        details: 'GitHub client not properly initialized'
      });
    }

    console.log(`Starting analysis for ${owner}/${repo}`);

    // Fetch repository data with timeout handling and better error handling
    const fetchWithTimeout = async (promise, timeout = 10000) => {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Request timeout')), timeout);
      });
      try {
        return await Promise.race([promise, timeoutPromise]);
      } catch (error) {
        console.error('Request failed:', {
          error: error.message,
          timeout,
          stack: error.stack,
          status: error.status,
          response: error.response?.data
        });
        throw error;
      }
    };

    // Fetch repository data with individual timeouts and error handling
    let repoData, languages, commits, issues, pullRequests;
    try {
      console.log('Fetching repository data...');
      [repoData, languages, commits, issues, pullRequests] = await Promise.all([
        fetchWithTimeout(req.octokit.repos.get({ owner, repo }))
          .catch(error => {
            console.error('Failed to fetch repository data:', {
              error: error.message,
              status: error.status,
              response: error.response?.data
            });
            throw new Error(`Failed to fetch repository data: ${error.message}`);
          }),
        fetchWithTimeout(req.octokit.repos.listLanguages({ owner, repo }))
          .catch(error => {
            console.warn('Failed to fetch languages:', error.message);
            return { data: {} };
          }),
        fetchWithTimeout(req.octokit.repos.listCommits({ owner, repo, per_page: 100 }))
          .catch(error => {
            console.warn('Failed to fetch commits:', error.message);
            return { data: [] };
          }),
        fetchWithTimeout(req.octokit.issues.listForRepo({ owner, repo, state: 'all' }))
          .catch(error => {
            console.warn('Failed to fetch issues:', error.message);
            return { data: [] };
          }),
        fetchWithTimeout(req.octokit.pulls.list({ owner, repo, state: 'all' }))
          .catch(error => {
            console.warn('Failed to fetch pull requests:', error.message);
            return { data: [] };
          })
      ]);
      console.log('Repository data fetched successfully');
    } catch (error) {
      console.error('Failed to fetch repository data:', {
        error: error.message,
        stack: error.stack,
        status: error.status,
        response: error.response?.data
      });
      return res.status(500).json({
        error: 'Failed to fetch repository data',
        details: error.message,
        type: 'GITHUB_API_ERROR',
        status: error.status,
        response: error.response?.data
      });
    }

    // Validate repository data
    if (!repoData || !repoData.data) {
      console.error('Invalid repository data received:', { repoData });
      return res.status(500).json({
        error: 'Invalid repository data',
        details: 'Failed to fetch valid repository information',
        data: repoData
      });
    }

    console.log('Repository data validation passed');

    // Try to get package.json with timeout and error handling
    let dependencies = { data: null };
    try {
      dependencies = await fetchWithTimeout(req.octokit.repos.getContent({ owner, repo, path: 'package.json' }))
        .catch(error => {
          if (error.status !== 404) {
            console.warn('Error fetching package.json:', error.message);
          }
          return { data: null };
        });
    } catch (error) {
      console.warn('No package.json found:', error.message);
    }

    // Prepare data for analysis with validation and default values
    const analysisData = {
      name: repoData.data.name || 'Unknown',
      description: repoData.data.description || 'No description provided',
      language: repoData.data.language || 'Not specified',
      topics: repoData.data.topics || [],
      stars: repoData.data.stargazers_count || 0,
      forks: repoData.data.forks_count || 0,
      openIssues: repoData.data.open_issues_count || 0,
      languages: Object.keys(languages?.data || {}),
      commitCount: commits?.data?.length || 0,
      issueCount: issues?.data?.length || 0,
      prCount: pullRequests?.data?.length || 0,
      hasDependencies: !!dependencies?.data,
      visibility: repoData.data.private ? 'private' : 'public',
      size: repoData.data.size || 0,
      defaultBranch: repoData.data.default_branch || 'main',
      createdAt: repoData.data.created_at || new Date().toISOString(),
      updatedAt: repoData.data.updated_at || new Date().toISOString()
    };

    console.log('Analysis data prepared:', analysisData);

    // Generate analysis based on repository data
    try {
      const repoLanguages = [analysisData.language, ...analysisData.languages.slice(0, 2)].filter(Boolean);
      const hasDependencies = analysisData.hasDependencies;
      const hasIssues = analysisData.openIssues > 0;
      const hasRecentActivity = analysisData.commitCount > 0;
      const hasMultipleLanguages = repoLanguages.length > 1;
      const isNewRepo = new Date(analysisData.createdAt) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const isActiveRepo = new Date(analysisData.updatedAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      
      const analysis = {
        technologies: repoLanguages,
        completion: isNewRepo ? 25 : (isActiveRepo ? 75 : 50),
        complexity: hasMultipleLanguages ? "High" : "Medium",
        codeQuality: [
          hasDependencies ? "Uses dependency management" : "No dependency management detected",
          hasIssues ? "Has open issues" : "No open issues",
          hasRecentActivity ? "Recent commit activity" : "No recent activity",
          hasMultipleLanguages ? "Multi-language project" : "Single language project",
          isActiveRepo ? "Active development" : "Limited recent activity",
          analysisData.visibility === 'private' ? "Private repository" : "Public repository"
        ],
        technicalDebt: [
          hasIssues ? "Open issues need attention" : "No immediate technical debt",
          !hasDependencies ? "Consider adding dependency management" : "Dependencies managed",
          "Regular maintenance recommended",
          hasMultipleLanguages ? "Consider consolidating languages" : "Language stack is focused",
          !isActiveRepo ? "Repository needs updates" : "Regular updates maintained"
        ],
        recommendations: [
          hasIssues ? "Address open issues" : "Keep up with maintenance",
          !hasDependencies ? "Consider adding dependency management" : "Keep dependencies updated",
          "Regular code reviews recommended",
          hasMultipleLanguages ? "Consider language consolidation" : "Maintain current language stack",
          isNewRepo ? "Focus on initial setup and documentation" : "Continue regular maintenance",
          analysisData.visibility === 'private' ? "Consider adding security scanning" : "Maintain public documentation"
        ]
      };
      
      console.log('Analysis generated successfully');

      // Return success response
      return res.json({
        repository: analysisData,
        analysis,
        status: 'success'
      });
    } catch (error) {
      console.error('Analysis generation error:', {
        error: error.message,
        stack: error.stack
      });
      return res.status(500).json({
        error: 'Analysis generation failed',
        details: error.message,
        type: 'ANALYSIS_ERROR'
      });
    }
  } catch (error) {
    console.error('Repository Analysis Error:', {
      message: error.message,
      stack: error.stack,
      status: error.status,
      code: error.code,
      response: error.response?.data,
      name: error.name
    });
    
    // Send a more informative error response
    return res.status(500).json({
      error: 'Analysis failed',
      details: error.message,
      type: error.name,
      code: error.code,
      status: error.status || 500,
      response: error.response?.data
    });
  }
});

// Function to analyze code samples from the repository
const analyzeCodeSamples = async (octokit, owner, repo) => {
  try {
    // Get the default branch
    const repoInfo = await octokit.repos.get({ owner, repo });
    const defaultBranch = repoInfo.data.default_branch;

    // Get tree of the repository to find files
    const tree = await octokit.git.getTree({
      owner,
      repo,
      tree_sha: defaultBranch,
      recursive: 1
    });
    
    // Filter for code files, limit to analyze main types
    const codeFiles = tree.data.tree.filter(item => 
      item.type === 'blob' && 
      /\.(js|jsx|ts|tsx|py|java|go|rb|php|cs|html|css)$/.test(item.path)
    ).slice(0, 5); // Analyze up to 5 files
    
    // Fetch and analyze each file
    const codeExamples = [];
    for (const file of codeFiles) {
      try {
        const content = await octokit.git.getBlob({
          owner,
          repo,
          file_sha: file.sha
        });
        
        const code = Buffer.from(content.data.content, 'base64').toString();
        
        // Basic code analysis based on file type
        const fileExt = file.path.split('.').pop().toLowerCase();
        const isTest = file.path.includes('test') || file.path.includes('spec');
        const hasComments = (code.match(/\/\/|\/\*|\*\/|#|<!--/g) || []).length > 0;
        const lineCount = code.split('\n').length;
        
        // Extract a reasonable code snippet (first ~10 lines)
        const codeSnippet = code.split('\n').slice(0, 10).join('\n');
        
        codeExamples.push({
          type: isTest ? 'best_practice' : 'issue',
          title: isTest ? 'Test file detected' : `Code review for ${file.path}`,
          location: file.path,
          code: codeSnippet,
          comment: hasComments ? 
            'Code includes comments which is good for maintainability' : 
            'Consider adding more comments to improve code readability'
        });
      } catch (error) {
        console.error(`Error analyzing file ${file.path}:`, error);
      }
    }
    
    return codeExamples;
  } catch (error) {
    console.error('Code sample analysis error:', error);
    return [];
  }
};

// Calculate code quality score based on repository data
const calculateCodeQualityScore = (repo, commits) => {
  // Base score starts at 50
  let score = 50;
  
  // Factor 1: Commit frequency (active development)
  if (commits.data.length > 100) score += 15;
  else if (commits.data.length > 50) score += 10;
  else if (commits.data.length > 20) score += 5;
  
  // Factor 2: Repository age and maintenance
  const ageInDays = (new Date() - new Date(repo.data.created_at)) / (1000 * 60 * 60 * 24);
  if (ageInDays > 365 && repo.data.updated_at) score += 10; // Maintained for over a year
  
  // Factor 3: Stars as a quality indicator
  if (repo.data.stargazers_count > 1000) score += 15;
  else if (repo.data.stargazers_count > 100) score += 10;
  else if (repo.data.stargazers_count > 10) score += 5;
  
  // Cap score at 100
  return Math.min(score, 100);
};

// Calculate maintainability score
const calculateMaintainabilityScore = (repo, issues, pullRequests) => {
  let score = 50;
  
  // Factor 1: Issue resolution rate
  const openIssues = repo.data.open_issues_count;
  const totalIssues = issues.data.length;
  
  if (totalIssues > 0) {
    const resolvedRatio = 1 - (openIssues / totalIssues);
    score += Math.round(resolvedRatio * 20); // Up to 20 points for issue resolution
  }
  
  // Factor 2: Pull request activity
  if (pullRequests.data.length > 20) score += 15;
  else if (pullRequests.data.length > 10) score += 10;
  else if (pullRequests.data.length > 5) score += 5;
  
  // Factor 3: Recent activity
  const lastUpdated = new Date(repo.data.updated_at);
  const daysSinceUpdate = (new Date() - lastUpdated) / (1000 * 60 * 60 * 24);
  
  if (daysSinceUpdate < 7) score += 15; // Updated in last week
  else if (daysSinceUpdate < 30) score += 10; // Updated in last month
  else if (daysSinceUpdate < 90) score += 5; // Updated in last 3 months
  
  return Math.min(score, 100);
};

// Calculate security score
const calculateSecurityScore = (repo) => {
  let score = 60; // Start with a base score
  
  // Factor 1: Is it actively maintained? (security patches)
  const lastUpdated = new Date(repo.data.updated_at);
  const daysSinceUpdate = (new Date() - lastUpdated) / (1000 * 60 * 60 * 24);
  
  if (daysSinceUpdate < 30) score += 20; // Updated in last month
  else if (daysSinceUpdate < 90) score += 10; // Updated in last 3 months
  else if (daysSinceUpdate > 365) score -= 20; // Not updated in over a year
  
  // Factor 2: Public vs Private (private repos are generally more secure)
  if (repo.data.private) score += 10;
  
  // Factor 3: Open issues that might indicate security problems
  if (repo.data.open_issues_count > 10) score -= 10;
  
  return Math.min(Math.max(score, 0), 100); // Ensure score is between 0-100
};

// Calculate documentation score
const calculateDocumentationScore = async (octokit, owner, repo, repoData) => {
  let score = 40; // Base score
  
  try {
    // Check for README file existence
    try {
      const readme = await octokit.repos.getReadme({ owner, repo });
      if (readme.data) {
        score += 25; // Big points for having a README
        
        // Check README size - comprehensive READMEs are better
        const content = Buffer.from(readme.data.content, 'base64').toString();
        if (content.length > 5000) score += 15;
        else if (content.length > 2000) score += 10;
        else if (content.length > 500) score += 5;
      }
    } catch (error) {
      // No README found
    }
    
    // Check for documentation folder or wiki
    try {
      const docs = await octokit.repos.getContent({ owner, repo, path: 'docs' });
      if (docs.data && Array.isArray(docs.data)) {
        score += 20 * Math.min(docs.data.length / 5, 1); // Up to 20 points for docs files
      }
    } catch (error) {
      // No docs folder found
    }
    
    // Check if wiki is enabled and has content
    if (repoData.data.has_wiki) {
      score += 10;
    }
    
  } catch (error) {
    console.error('Error calculating documentation score:', error);
  }
  
  return Math.min(score, 100);
};

// Calculate test coverage score
const calculateTestCoverageScore = async (octokit, owner, repo) => {
  let score = 30; // Base score
  
  try {
    // Get repository tree to check for test files
    const tree = await octokit.git.getTree({
      owner,
      repo,
      tree_sha: 'HEAD',
      recursive: 1
    });
    
    // Count test files vs total code files
    const allFiles = tree.data.tree.filter(item => 
      item.type === 'blob' && 
      /\.(js|jsx|ts|tsx|py|java|go|rb|php|cs)$/.test(item.path)
    );
    
    const testFiles = allFiles.filter(item => 
      /test|spec|__tests__|Test\.|\btest\b/.test(item.path)
    );
    
    if (allFiles.length > 0) {
      const testRatio = testFiles.length / allFiles.length;
      score += Math.min(Math.round(testRatio * 100), 70); // Up to 70 more points based on test ratio
    }
    
  } catch (error) {
    console.error('Error calculating test score:', error);
  }
  
  return Math.min(score, 100);
};

// Get repository health score
router.get('/:owner/:repo/health', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;
    const { analyze_code, detailed } = req.query;
    
    console.log(`Calculating health score for ${owner}/${repo}`, {
      analyze_code: analyze_code === 'true',
      detailed: detailed === 'true'
    });

    // Fetch repository data
    const [repoData, issues, pullRequests, commits] = await Promise.all([
      req.octokit.repos.get({ owner, repo }),
      req.octokit.issues.listForRepo({ owner, repo, state: 'all' }),
      req.octokit.pulls.list({ owner, repo, state: 'all' }),
      req.octokit.repos.listCommits({ owner, repo, per_page: 100 })
    ]);
    
    // Get code samples if requested
    let codeExamples = [];
    if (analyze_code === 'true') {
      codeExamples = await analyzeCodeSamples(req.octokit, owner, repo);
    }

    // Calculate all health metrics
    const codeQualityScore = calculateCodeQualityScore(repoData, commits);
    const maintainabilityScore = calculateMaintainabilityScore(repoData, issues, pullRequests);
    const securityScore = calculateSecurityScore(repoData);
    const documentationScore = await calculateDocumentationScore(req.octokit, owner, repo, repoData);
    const testCoverageScore = await calculateTestCoverageScore(req.octokit, owner, repo);
    
    // Calculate overall score as weighted average
    const overallScore = Math.round(
      (codeQualityScore * 0.25) +
      (maintainabilityScore * 0.25) +
      (securityScore * 0.2) +
      (documentationScore * 0.15) +
      (testCoverageScore * 0.15)
    );

    // Initialize health data object
    const healthData = {
      overallScore,
      metrics: {
        codeQuality: codeQualityScore,
        maintainability: maintainabilityScore,
        security: securityScore,
        documentation: documentationScore,
        testCoverage: testCoverageScore
      },
      issues: {
        critical: 0,
        high: 0,
        medium: 0,
        low: issues.data.filter(issue => !issue.pull_request).length
      },
      recommendations: [],
      codeExamples
    };

    // Classify issues by severity (based on labels or other heuristics)
    issues.data.forEach(issue => {
      // Skip pull requests
      if (issue.pull_request) return;
      
      // Check for severity labels
      if (issue.labels && issue.labels.length > 0) {
        const labels = issue.labels.map(label => label.name.toLowerCase());
        
        if (labels.some(label => label.includes('critical') || label.includes('security'))) {
          healthData.issues.critical++;
          healthData.issues.low--;
        } else if (labels.some(label => label.includes('high') || label.includes('important'))) {
          healthData.issues.high++;
          healthData.issues.low--;
        } else if (labels.some(label => label.includes('medium') || label.includes('enhancement'))) {
          healthData.issues.medium++;
          healthData.issues.low--;
        }
      }
    });

    // Generate AI recommendations based on analysis
    try {
      const prompt = `As a repository health analysis system, provide specific, actionable recommendations for this repository:
      
      Repository: ${repoData.data.name}
      Language: ${repoData.data.language || 'Not specified'}
      Stars: ${repoData.data.stargazers_count}
      Forks: ${repoData.data.forks_count}
      Issues: ${issues.data.length} (${repoData.data.open_issues_count} open)
      Pull Requests: ${pullRequests.data.length}
      Commits: ${commits.data.length}
      
      Health Scores:
      - Code Quality: ${codeQualityScore}/100
      - Maintainability: ${maintainabilityScore}/100
      - Security: ${securityScore}/100
      - Documentation: ${documentationScore}/100
      - Test Coverage: ${testCoverageScore}/100
      
      Based on these metrics, provide 5-7 specific, actionable recommendations to improve this repository's health.
      Each recommendation should be concise (max 1 sentence) and directly address specific improvement areas.
      Don't use generic advice - tailor recommendations to the repository's unique profile and scores.`;

      const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system",
            content: "You are a repository health analysis API. Provide concise, actionable recommendations tailored to this specific repository's metrics. Each recommendation should be one clear sentence with specific advice."
          },
          { 
            role: "user", 
            content: prompt 
          }
        ],
        temperature: 0.1,
        max_tokens: 500
      });

      healthData.recommendations = completion.choices[0].message.content
        .split('\n')
        .filter(line => line.trim() !== '')
        .map(line => line.replace(/^\d+\.\s+/, '').trim()) // Remove numbered list markers
        .filter(line => line.length > 0);
      
      // If no recommendations generated, provide fallback
      if (healthData.recommendations.length === 0) {
        throw new Error('No recommendations generated');
      }
    } catch (error) {
      console.error('OpenAI API error in health recommendations:', error);
      
      // Generate recommendations based on scores
      healthData.recommendations = [];
      
      if (codeQualityScore < 60) {
        healthData.recommendations.push("Improve code quality by implementing a linter and enforcing consistent coding standards.");
      }
      
      if (maintainabilityScore < 60) {
        healthData.recommendations.push("Reduce technical debt by addressing open issues and implementing more modular code architecture.");
      }
      
      if (securityScore < 60) {
        healthData.recommendations.push("Enhance security by implementing regular dependency updates and security scanning in your CI/CD pipeline.");
      }
      
      if (documentationScore < 60) {
        healthData.recommendations.push("Improve documentation with more comprehensive README, code comments, and API references.");
      }
      
      if (testCoverageScore < 60) {
        healthData.recommendations.push("Increase test coverage for critical components and implement automated testing in your workflow.");
      }
      
      // Add general recommendations
      healthData.recommendations.push("Regularly review and address open issues to maintain repository health.");
      healthData.recommendations.push("Keep dependencies updated to avoid vulnerabilities and technical debt.");
    }

    console.log(`Health score calculation completed: ${overallScore}/100`);
    res.json(healthData);
  } catch (error) {
    console.error('Health Score Error:', error);
    res.status(500).json({
      error: 'Health score calculation failed',
      details: error.message
    });
  }
});

// Get repository activity
router.get('/:owner/:repo/activity', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;

    // Fetch activity data
    const [commits, issues, pullRequests] = await Promise.all([
      req.octokit.repos.listCommits({ owner, repo, per_page: 100 }),
      req.octokit.issues.listForRepo({ owner, repo, state: 'all' }),
      req.octokit.pulls.list({ owner, repo, state: 'all' })
    ]);

    // Process activity data with more detailed analysis
    const activityData = {
      // Basic activity counts
      commits: commits.data.map(commit => ({
        date: commit.commit.author.date,
        count: 1,
        author: commit.author ? commit.author.login : 'unknown',
        message: commit.commit.message.split('\n')[0]
      })),
      issues: issues.data.map(issue => ({
        date: issue.created_at,
        count: 1
      })),
      pullRequests: pullRequests.data.map(pr => ({
        date: pr.created_at,
        count: 1
      }))
    };

    res.json(activityData);
  } catch (error) {
    console.error('Activity Data Error:', error);
    res.status(500).json({
      error: 'Failed to fetch activity data',
      details: error.message
    });
  }
});

// Get repository dependencies
router.get('/:owner/:repo/dependencies', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;

    // Fetch package.json
    try {
      const packageJson = await req.octokit.repos.getContent({
        owner,
        repo,
        path: 'package.json'
      });

      // Parse dependencies
      const dependencies = {
        production: [],
        development: []
      };

      if (packageJson.data.content) {
        const content = Buffer.from(packageJson.data.content, 'base64').toString();
        const parsed = JSON.parse(content);

        // Process production dependencies
        if (parsed.dependencies) {
          dependencies.production = Object.entries(parsed.dependencies).map(([name, version]) => ({
            name,
            version,
            size: '0MB' // You might want to fetch actual package sizes
          }));
        }

        // Process development dependencies
        if (parsed.devDependencies) {
          dependencies.development = Object.entries(parsed.devDependencies).map(([name, version]) => ({
            name,
            version,
            size: '0MB' // You might want to fetch actual package sizes
          }));
        }
      }

      res.json(dependencies);
    } catch (error) {
      if (error.status === 404) {
        // If package.json doesn't exist, return empty dependencies
        res.json({
          production: [],
          development: []
        });
      } else {
        throw error;
      }
    }
  } catch (error) {
    console.error('Dependencies Error:', error);
    res.status(500).json({
      error: 'Failed to fetch dependencies',
      details: error.message
    });
  }
});

// Add this to your repository.js file

// Analyze repository structure for documentation
router.get('/:owner/:repo/analyze-for-docs', checkGitHubToken, async (req, res) => {
  try {
    const { owner, repo } = req.params;
    console.log(`Analyzing repository structure for ${owner}/${repo}`);

    // Get repository info
    const repoInfo = await req.octokit.repos.get({ owner, repo });
    
    // Get default branch
    const defaultBranch = repoInfo.data.default_branch;

    // Get tree of the repository
    const tree = await req.octokit.git.getTree({
      owner,
      repo,
      tree_sha: defaultBranch,
      recursive: 1
    });

    // Identify key files to analyze
    const keyFiles = [
      // Look for configuration files
      'package.json',
      'tsconfig.json',
      'webpack.config.js',
      'vite.config.js',
      'next.config.js',
      '.env.example',
      'docker-compose.yml',
      'Dockerfile',
      // Look for main application files
      'src/index.js',
      'src/index.ts',
      'src/App.js',
      'src/App.tsx',
      'src/main.js',
      'src/main.ts',
      'src/main.jsx',
      'src/main.tsx',
      'app/index.js',
      'app/index.ts',
      'app/main.js',
      'app/main.ts',
      'app/main.jsx',
      'app/main.tsx',
      'public/index.html',
      'index.html',
      // API/server files
      'server.js',
      'api/index.js',
      // Documentation files
      'README.md'
    ];

    // Find files that exist in the repository
    const filesToAnalyze = tree.data.tree
      .filter(item => 
        item.type === 'blob' && 
        (keyFiles.includes(item.path) || 
         item.path.match(/^(src|app)\/(index|main|app)\.(js|ts|jsx|tsx)$/))
      )
      .slice(0, 10); // Limit to 10 key files to avoid excessive API calls

    // Fetch content of each file
    const fileContents = await Promise.all(
      filesToAnalyze.map(async file => {
        try {
          const content = await req.octokit.git.getBlob({
            owner,
            repo,
            file_sha: file.sha
          });
          
          const fileContent = Buffer.from(content.data.content, 'base64').toString();
          return {
            path: file.path,
            content: fileContent.length > 10000 ? 
              fileContent.substring(0, 10000) + '... (truncated)' : 
              fileContent
          };
        } catch (error) {
          console.error(`Error fetching file ${file.path}:`, error);
          return { path: file.path, content: 'Error: Could not fetch content' };
        }
      })
    );

    // Get languages used in the repository
    const languages = await req.octokit.repos.listLanguages({ owner, repo });

    // Get package.json if exists
    let dependencies = null;
    try {
      const packageJson = fileContents.find(file => file.path === 'package.json');
      if (packageJson) {
        const packageData = JSON.parse(packageJson.content);
        dependencies = {
          name: packageData.name,
          description: packageData.description,
          dependencies: packageData.dependencies || {},
          devDependencies: packageData.devDependencies || {}
        };
      }
    } catch (error) {
      console.error('Error parsing package.json:', error);
    }

    // Prepare repository analysis data
    const analysisData = {
      repository: {
        name: repoInfo.data.name,
        fullName: repoInfo.data.full_name,
        description: repoInfo.data.description,
        defaultBranch: repoInfo.data.default_branch,
        languages: languages.data,
        dependencies,
        isPrivate: repoInfo.data.private,
        hasIssues: repoInfo.data.has_issues,
        hasWiki: repoInfo.data.has_wiki,
        topics: repoInfo.data.topics,
        license: repoInfo.data.license,
        createdAt: repoInfo.data.created_at,
        updatedAt: repoInfo.data.updated_at
      },
      files: fileContents
    };

    res.json(analysisData);
  } catch (error) {
    console.error('Repository structure analysis error:', error);
    res.status(500).json({
      error: 'Failed to analyze repository structure',
      details: error.message
    });
  }
});

// Enhanced documentation generation endpoint
// Enhanced documentation generation endpoint
router.post('/generate-docs', checkGitHubToken, async (req, res) => {
  try {
    console.log('Received documentation generation request:', {
      docType: req.body.docType,
      repoName: req.body?.repoData?.name
    });
    
    const { repoData, docType, fileAnalysis } = req.body;
    
    if (!repoData || !docType) {
      console.error('Missing required parameters:', { repoData: !!repoData, docType });
      return res.status(400).json({
        error: 'Missing required parameters',
        details: 'Repository data and document type are required'
      });
    }
    
    // Validate document type
    const validTypes = ['readme', 'contributing', 'codeOfConduct', 'api'];
    if (!validTypes.includes(docType)) {
      console.error('Invalid document type:', { docType, validTypes });
      return res.status(400).json({
        error: 'Invalid document type',
        details: `Document type must be one of: ${validTypes.join(', ')}`
      });
    }

    // Validate OpenAI API key
    if (!process.env.OPENAI_API_KEY) {
      console.error('OpenAI API key is not configured');
      return res.status(500).json({
        error: 'Server configuration error',
        details: 'OpenAI API key is not configured'
      });
    }

    // Generate documentation based on repository data using OpenAI
    let systemPrompt;
    let userPrompt;
    
    // Build prompts based on document type (your existing switch case)
    switch (docType) {
      // Your existing cases...
      case 'readme':
        systemPrompt = "You are a documentation expert specialized in creating comprehensive README.md files for software projects. You analyze code to understand the project structure, purpose, and technology stack.";
        
        // Safely handle fileAnalysis, ensuring it's an object
        const safeFileAnalysis = fileAnalysis && typeof fileAnalysis === 'object' ? fileAnalysis : {};
        
        userPrompt = `Generate a professional and comprehensive README.md for a repository with the following details:
        
Repository name: ${repoData.name || 'Unnamed Project'}
Description: ${repoData.description || 'No description provided'}
Primary language: ${repoData.language || 'Not specified'}
Topics/tags: ${Array.isArray(repoData.topics) ? repoData.topics.join(', ') : 'None'}

${safeFileAnalysis.projectPurpose ? `
Based on the code analysis, this project appears to be:
${safeFileAnalysis.projectPurpose}

The main technologies used include:
${Array.isArray(safeFileAnalysis.technologies) ? safeFileAnalysis.technologies.join(', ') : 'Not specified'}

Key features identified:
${Array.isArray(safeFileAnalysis.features) ? safeFileAnalysis.features.join('\n') : 'Not specified'}
` : ''}

Create a comprehensive README with the following sections:
1. Project Title with badges for build status, version, etc.
2. Project Overview - Concise description of what this project does
3. Key Features - Detailed bullet points on capabilities
4. Technology Stack - List of all technologies, libraries and frameworks used
5. Prerequisites - What's needed to run this project
6. Installation - Step-by-step instructions
7. Usage - How to use the project with code examples
8. API Reference (if applicable)
9. Configuration - Environment variables and settings
10. Testing - How to run tests
11. Deployment - How to deploy
12. Contributing - Guidelines for contributors
13. License
14. Acknowledgements (if applicable)

Use markdown formatting including:
- Proper headings (h1, h2, h3)
- Code blocks with appropriate language syntax highlighting
- Tables where appropriate
- Links to important resources
- Badges where relevant

Make the content professional, informative, and tailored specifically to this project based on the code analysis. Do not use generic placeholder text.`;
        break;
      
      // Keep your other cases...
      case 'contributing':
        systemPrompt = "You are a documentation expert specialized in creating CONTRIBUTING.md files for software projects.";
        userPrompt = `Generate a comprehensive CONTRIBUTING.md for a repository with the following details:
        
Repository name: ${repoData.name || 'Unnamed Project'}
Description: ${repoData.description || 'No description provided'}
Primary language: ${repoData.language || 'Not specified'}

Include the following sections:
1. Introduction
2. Code of Conduct reference
3. How to contribute (fork, branch, commit, PR workflow)
4. Development environment setup
5. Testing guidelines
6. Pull request process
7. Issue reporting guidelines

Use markdown formatting and keep the content professional but friendly. Do not include any placeholder text.`;
        break;
        
      case 'codeOfConduct':
        systemPrompt = "You are a documentation expert specialized in creating CODE_OF_CONDUCT.md files for software projects.";
        userPrompt = `Generate a standard Code of Conduct file (CODE_OF_CONDUCT.md) for a repository.

Use the Contributor Covenant as a basis, including sections on:
1. Our Pledge
2. Our Standards (acceptable and unacceptable behavior)
3. Enforcement Responsibilities
4. Scope
5. Enforcement
6. Attribution

Use markdown formatting and keep the content professional, inclusive, and comprehensive. Do not include any placeholder text.`;
        break;
        
      case 'api':
        systemPrompt = "You are a documentation expert specialized in creating API documentation for software projects.";
        userPrompt = `Generate comprehensive API documentation for a repository with the following details:
        
Repository name: ${repoData.name || 'Unnamed Project'}
Description: ${repoData.description || 'No description provided'}
Primary language: ${repoData.language || 'Not specified'}

Include the following sections:
1. Authentication
2. Base URL
3. Error Handling
4. Rate Limiting
5. Endpoints (with examples for GET, POST, PUT, DELETE operations)
6. Request/Response formats

Use markdown formatting and keep the content professional, technical, and comprehensive. Do not include any placeholder text.`;
        break;
    }

    console.log('Calling OpenAI API for documentation generation', {
      model: "gpt-3.5-turbo-16k",
      docType,
      promptLength: userPrompt.length
    });

    // Call OpenAI API with proper error handling
    try {
      const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo-16k", // Use a model with larger context
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        temperature: 0.1,
        max_tokens: 4000 // Increase token limit for more comprehensive docs
      });

      // Extract and send the generated documentation
      const documentation = completion.choices[0].message.content;
      
      console.log('Documentation generated successfully', {
        docType,
        length: documentation.length
      });
      
      res.json({
        documentation,
        type: docType,
        status: 'success'
      });
    } catch (openaiError) {
      console.error('OpenAI API Error:', {
        message: openaiError.message,
        status: openaiError.status,
        stack: openaiError.stack,
        response: openaiError.response?.data
      });
      
      return res.status(500).json({
        error: 'OpenAI API error',
        details: openaiError.message,
        type: 'OPENAI_API_ERROR'
      });
    }
    
  } catch (error) {
    console.error('Documentation Generation Error:', {
      message: error.message,
      stack: error.stack,
      name: error.name,
      code: error.code
    });
    
    res.status(500).json({
      error: 'Failed to generate documentation',
      details: error.message,
      type: 'DOCUMENTATION_GENERATION_ERROR'
    });
  }
});
export default router;