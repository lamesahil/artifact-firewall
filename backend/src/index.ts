import express from 'express';
import cors from 'cors';
import multer from 'multer';
import dotenv from 'dotenv';
import { sanitizeText, sanitizeJson } from './engine.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Allowed origins — add localhost for local dev, Vercel URL for production
const ALLOWED_ORIGINS = [
  'https://artifact-firewall.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

const corsOptions: Parameters<typeof cors>[0] = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. curl, Postman, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS: origin '${origin}' is not allowed.`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true,
  optionsSuccessStatus: 204, // Some legacy browsers choke on 200 for OPTIONS
};

// Apply CORS middleware globally
app.use(cors(corsOptions));

// Explicitly handle preflight OPTIONS requests for all routes
app.options('*', cors(corsOptions));

// Parse JSON and URL-encoded bodies (limit to 50MB for large HAR files)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Configure multer for memory storage (never save files to disk)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  }
});

// Root check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Secret Sanitizer API is running' });
});

// Core sanitize endpoint
app.post('/api/sanitize', upload.single('file'), (req: express.Request, res: express.Response) => {
  try {
    // 1. Extract settings / filter toggles
    let enabledSettings = { jwt: true, aws: true, database: true, generic: true };

    const parseSettingVal = (val: any): boolean => {
      if (val === undefined || val === null) return true;
      if (val === 'false' || val === false) return false;
      return true;
    };

    // Settings can be passed as JSON string or form fields
    if (req.body.settings) {
      try {
        const parsed = typeof req.body.settings === 'string' 
          ? JSON.parse(req.body.settings) 
          : req.body.settings;
        enabledSettings = {
          jwt: parseSettingVal(parsed.jwt),
          aws: parseSettingVal(parsed.aws),
          database: parseSettingVal(parsed.database),
          generic: parseSettingVal(parsed.generic)
        };
      } catch (e) {
        // Fallback if settings parsing fails
      }
    } else {
      // Direct form fields
      enabledSettings = {
        jwt: parseSettingVal(req.body.jwt),
        aws: parseSettingVal(req.body.aws),
        database: parseSettingVal(req.body.database),
        generic: parseSettingVal(req.body.generic)
      };
    }

    // 2. Handle File Upload or Raw Text
    const file = req.file;
    const rawText = req.body.text;

    if (!file && !rawText) {
      return res.status(400).json({ error: 'Missing payload. Upload a file or provide raw text.' });
    }

    // Processing File
    if (file) {
      const fileName = file.originalname;
      const fileExtension = fileName.split('.').pop()?.toLowerCase();
      const content = file.buffer.toString('utf-8');

      // Detect if file is JSON/HAR
      const isJsonOrHar = fileExtension === 'json' || fileExtension === 'har' || file.mimetype === 'application/json';

      if (isJsonOrHar) {
        try {
          const jsonObj = JSON.parse(content);
          const result = sanitizeJson(jsonObj, enabledSettings);
          return res.json({
            fileName,
            fileType: fileExtension,
            isJson: true,
            originalContent: content,
            sanitizedContent: JSON.stringify(result.sanitized, null, 2),
            stats: result.stats,
            details: result.details
          });
        } catch (e) {
          // If JSON parsing fails, fall back to plain text sanitization
          const result = sanitizeText(content, enabledSettings);
          return res.json({
            fileName,
            fileType: fileExtension,
            isJson: false,
            originalContent: content,
            sanitizedContent: result.sanitized,
            stats: result.stats,
            details: result.details
          });
        }
      } else {
        // Handle as plain text (.txt, etc.)
        const result = sanitizeText(content, enabledSettings);
        return res.json({
          fileName,
          fileType: fileExtension || 'txt',
          isJson: false,
          originalContent: content,
          sanitizedContent: result.sanitized,
          stats: result.stats,
          details: result.details
        });
      }
    }

    // Processing Raw Text
    if (rawText) {
      const result = sanitizeText(rawText, enabledSettings);
      return res.json({
        isJson: false,
        originalContent: rawText,
        sanitizedContent: result.sanitized,
        stats: result.stats,
        details: result.details
      });
    }

  } catch (error: any) {
    console.error('Sanitization API Error:', error);
    return res.status(500).json({ error: 'Internal Server Error during sanitization: ' + error.message });
  }
});

// Start Express Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
