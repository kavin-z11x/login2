/**
 * Kalai Spoken English Student Portal Backend
 * ----------------------------------------------------
 * This Express server acts as a secure proxy and API bridge between the
 * client-side frontend and the Google Sheets database (via Google Apps Script).
 * 
 * Features:
 * 1. JWT Authentication: Verifies credentials and signs secure JSON Web Tokens.
 * 2. ID Spoofing Protection: Decodes JWT on secure requests and overrides requested IDs.
 * 3. In-memory Caching: Caches queries for 3 minutes to avoid Google Sheet cold-starts.
 * 4. Static Hosting: Serves login and dashboard HTML interfaces on port 3005.
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3005;

// Secret key for signing JSON Web Tokens. 
// In production environments, store this in process.env.JWT_SECRET.
const JWT_SECRET = process.env.JWT_SECRET || 'kalai_spoken_english_super_secure_jwt_secret_key_2026';

// Google Apps Script Web App Deployment URL linked to the Google Sheet spreadsheet
const GAS_URL = "https://script.google.com/macros/s/AKfycbzkEotPVqeT916NxBtlUNldAUVbYkmqIqoKwXTNo9jzv0CIXW4I-nwchoIz0PzAs7Ok/exec";

// Express Middleware setup
app.use(cors()); // Allow cross-origin requests from frontend layouts
app.use(express.json()); // Support parsing of application/json request bodies
app.use(express.urlencoded({ extended: true })); // Support parsing of URL-encoded request bodies

// Host all static frontend web pages out of the './public' folder
app.use(express.static(path.join(__dirname, 'public')));

// --- IN-MEMORY CACHE STORAGE ENGINE ---
const cacheStore = {}; // Holds cached API data in-memory
const CACHE_TTL = 3 * 60 * 1000; // Cache Time-to-Live (3 minutes in milliseconds)

/**
 * Retrieve data from memory cache if it exists and hasn't expired.
 * @param {string} key - Cache lookup key
 * @returns {any|null} The cached payload or null if miss/expired
 */
function getCachedData(key) {
  const cached = cacheStore[key];
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return cached.data;
  }
  return null;
}

/**
 * Save API payloads to cache memory with a timestamp.
 * @param {string} key - Cache storage key
 * @param {any} data - JSON payload to cache
 */
function setCachedData(key, data) {
  cacheStore[key] = {
    data: data,
    timestamp: Date.now()
  };
}

/**
 * Evict keys from the cache to ensure updates are reflected immediately.
 * Called when student profile registers or test scores are added.
 * @param {string} studentId - Target student ID to invalidate
 */
function clearCache(studentId) {
  console.log(`[Cache] Invalidating cache for student updates...`);
  if (studentId) {
    delete cacheStore[`getStudentProfile_${studentId}`];
    delete cacheStore[`getPoints_${studentId}`];
  } else {
    // Evict all keys if no specific ID is given
    for (const key in cacheStore) {
      delete cacheStore[key];
    }
  }
  // Always invalidate the admin students directory list
  delete cacheStore[`getStudents`];
}

// --- API ROUTE HANDLERS ---

/**
 * Main GET endpoint: Handles login verification (public) 
 * and secures all spreadsheet read actions (JWT token authenticated).
 */
app.get('/api', async (req, res) => {
  const { action, id } = req.query;
  
  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  // --- PUBLIC ACTION: verifyLogin ---
  // Contacts Google Sheets to check password; returns signed JWT token on success.
  if (action === 'verifyLogin') {
    try {
      const queryParams = new URLSearchParams(req.query).toString();
      const targetUrl = `${GAS_URL}?${queryParams}`;
      
      console.log(`[Login] Authenticating user ID: ${id}`);
      const response = await fetch(targetUrl);
      const data = await response.json();

      if (data.status === 'success') {
        // Generate a cryptographically signed JWT token holding the student payload
        const token = jwt.sign(
          { studentId: id, studentName: data.name },
          JWT_SECRET,
          { expiresIn: '24h' } // Token session lasts for 24 hours
        );
        
        console.log(`[Login] JWT Issued successfully for ID: ${id}`);
        return res.json({
          status: 'success',
          name: data.name,
          token: token
        });
      } else {
        return res.json(data);
      }
    } catch (error) {
      console.error("Login Verification Error:", error);
      return res.status(502).json({ error: "Failed to verify credentials", details: error.message });
    }
  }

  // --- SECURED ACTIONS: getStudentProfile, getPoints, getStudents ---
  // Requires a valid Authorization: Bearer <token> header.
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token from header

  if (!token) {
    console.log(`[Auth Warning] Blocked unauthenticated action request: ${action}`);
    return res.status(401).json({ error: 'Unauthorized: Access token is missing' });
  }

  try {
    // Decrypt and verify JWT token integrity using the secret key
    const decodedUser = jwt.verify(token, JWT_SECRET);
    
    // ANTI-SPOOFING OVERWRITE:
    // Force spreadsheet query ID parameter to match the logged-in JWT token studentId.
    // This stops users from tampering with query IDs to view another student's details.
    const verifiedId = decodedUser.studentId;
    req.query.id = verifiedId;

    const cacheKey = `${action}_${verifiedId}`;

    // Serve from cache if available
    const cachedData = getCachedData(cacheKey);
    if (cachedData) {
      console.log(`[Proxy GET] [CACHE HIT] Serving from memory: ${cacheKey}`);
      return res.json(cachedData);
    }

    // Cache Miss -> Forward GET request directly to Google Sheets script
    const queryParams = new URLSearchParams(req.query).toString();
    const targetUrl = `${GAS_URL}?${queryParams}`;
    
    console.log(`[Proxy GET] [CACHE MISS] Fetching from Google Sheets: ${targetUrl}`);
    const response = await fetch(targetUrl);
    const data = await response.json();

    // Cache responses from successful sheet queries
    if (!data.error && data.status !== 'error') {
      console.log(`[Proxy GET] Caching response for key: ${cacheKey}`);
      setCachedData(cacheKey, data);
    }

    res.json(data);
  } catch (err) {
    console.error(`[Auth Error] Token verification failed for action: ${action}`, err.message);
    return res.status(403).json({ error: 'Forbidden: Invalid or expired access token' });
  }
});

/**
 * POST endpoint: Forwards data writes (e.g. register, addPoints) 
 * directly to Google Sheet web app. Enforces JWT token checks.
 */
app.post('/api', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Access token is missing' });
  }

  try {
    // Validate JWT session
    const decodedUser = jwt.verify(token, JWT_SECRET);
    
    // For updates, force studentId to match JWT context
    if (req.body.formData && req.body.action === 'addPoints') {
      req.body.formData.studentId = decodedUser.studentId;
    }

    console.log(`[Proxy POST] Forwarding update query to Google Sheets...`);
    const response = await fetch(GAS_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();

    // Invalidate caches to ensure fresh data loads on next request
    const targetStudentId = decodedUser.studentId;
    console.log(`[Proxy POST] Action succeeded. Invaliding caches for student ID: ${targetStudentId}`);
    clearCache(targetStudentId);

    res.json(data);
  } catch (error) {
    console.error("Proxy POST Error:", error);
    res.status(502).json({ error: "Failed to post update to Sheets", details: error.message });
  }
});

// Default server index redirects to the login layout
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'student_login.html'));
});

// Initialize and spin up Express Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 Secure JWT Caching Proxy Server running on port ${PORT}`);
  console.log(`📂 Serving static files from "./public"`);
  console.log(`🔒 Authentication: JWT Tokens active`);
  console.log(`⚡ In-memory cache enabled (TTL: 3 minutes)`);
  console.log(`=======================================================`);
});
