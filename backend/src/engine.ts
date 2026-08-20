export interface SanitizationStats {
  jwt: number;
  aws: number;
  database: number;
  generic: number;
}

export interface RedactedDetail {
  type: string;
  originalSnippet: string;
  placeholder: string;
}

export interface SanitizationResult {
  sanitized: any; // Can be string or parsed object
  stats: SanitizationStats;
  details: RedactedDetail[];
}

// Regex definitions
const REGEX_PATTERNS = {
  jwt: /\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b/g,
  awsAccessKey: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
  awsSecretKeyContext: /(?:aws_secret_access_key|aws_secret|secret_key|aws_key)[\s:='"]+([A-Za-z0-9/+=]{40})/gi,
  databaseUri: /\b((?:postgres|postgresql|mongodb(?:\+srv)?):\/\/[^:\s]+:[^@\s]+@[^/\s]+(?::\d+)?(?:[^\s?]+)?(?:\?[^\s]+)?)\b/g,
  googleApiKey: /\b(AIza[A-Za-z0-9-_]{35})\b/g,
  slackToken: /\b(xox[bapr]-[0-9a-zA-Z-]{10,64})\b/g,
  stripeApiKey: /\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,48})\b/g,
  genericKeyContext: /(?:api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?password)[\s:='"]+([A-Za-z0-9-._~+/=]{16,64})/gi,
  bearerToken: /bearer\s+([A-Za-z0-9-._~+/=]{16,128})/gi
};

// Mask helper for security reports
function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return '...';
  }
  return `${secret.substring(0, 4)}...${secret.substring(secret.length - 4)}`;
}

// Helper to check if a key name suggests sensitive content (e.g. in JSON payloads)
const SENSITIVE_KEYS = [
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  'pwd',
  'secret',
  'token',
  'apikey',
  'api-key',
  'api_key',
  'pass',
  'passwd'
];

function isSensitiveKey(key: string): boolean {
  const normalizedKey = key.toLowerCase();
  return SENSITIVE_KEYS.some(sk => normalizedKey.includes(sk));
}

export function sanitizeText(
  text: string,
  enabled: Record<string, boolean> = { jwt: true, aws: true, database: true, generic: true }
): { sanitized: string; stats: SanitizationStats; details: RedactedDetail[] } {
  let sanitized = text;
  const stats: SanitizationStats = { jwt: 0, aws: 0, database: 0, generic: 0 };
  const details: RedactedDetail[] = [];

  const placeholder = '[REDACTED_SECRET]';

  // Helper to replace and record
  const runReplacement = (
    regex: RegExp,
    type: 'jwt' | 'aws' | 'database' | 'generic',
    captureGroupIndex: number = 0
  ) => {
    if (!enabled[type]) return;

    // Reset regex index
    regex.lastIndex = 0;

    let match;
    const matchesToReplace: Array<{ original: string; matchText: string }> = [];

    // Find all matches
    while ((match = regex.exec(sanitized)) !== null) {
      const matchText = match[0];
      const secret = match[captureGroupIndex] || matchText;

      // Avoid double-redacting
      if (secret === placeholder || secret.includes(placeholder)) {
        continue;
      }

      matchesToReplace.push({ original: secret, matchText });
    }

    // Replace matches (descending order of length/index to prevent offset issues)
    for (const item of matchesToReplace) {
      if (sanitized.includes(item.original)) {
        // Count and record
        stats[type]++;
        details.push({
          type,
          originalSnippet: maskSecret(item.original),
          placeholder
        });
        
        // Simple string replace all occurrences of this exact secret
        // Splitting and joining is safe and avoids regex escape issues
        sanitized = sanitized.split(item.original).join(placeholder);
      }
    }
  };

  // 1. Database URIs (replace first to prevent parsing parts as generic credentials)
  runReplacement(REGEX_PATTERNS.databaseUri, 'database');

  // 2. JWTs
  runReplacement(REGEX_PATTERNS.jwt, 'jwt');

  // 3. AWS Keys
  runReplacement(REGEX_PATTERNS.awsAccessKey, 'aws');
  runReplacement(REGEX_PATTERNS.awsSecretKeyContext, 'aws', 1);

  // 4. Specific Generic API Keys
  runReplacement(REGEX_PATTERNS.googleApiKey, 'generic');
  runReplacement(REGEX_PATTERNS.slackToken, 'generic');
  runReplacement(REGEX_PATTERNS.stripeApiKey, 'generic');

  // 5. Generic Context Patterns
  runReplacement(REGEX_PATTERNS.genericKeyContext, 'generic', 1);
  runReplacement(REGEX_PATTERNS.bearerToken, 'generic', 1);

  return { sanitized, stats, details };
}

export function sanitizeJson(
  obj: any,
  enabled: Record<string, boolean> = { jwt: true, aws: true, database: true, generic: true }
): SanitizationResult {
  const stats: SanitizationStats = { jwt: 0, aws: 0, database: 0, generic: 0 };
  const details: RedactedDetail[] = [];
  const placeholder = '[REDACTED_SECRET]';

  function mergeResult(res: { stats: SanitizationStats; details: RedactedDetail[] }) {
    stats.jwt += res.stats.jwt;
    stats.aws += res.stats.aws;
    stats.database += res.stats.database;
    stats.generic += res.stats.generic;
    details.push(...res.details);
  }

  function traverse(item: any, parentKey?: string): any {
    if (item === null || item === undefined) {
      return item;
    }

    if (typeof item === 'string') {
      // 1. Check if the string itself is a nested JSON string (common in HAR files like request/response bodies)
      const trimmed = item.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
          const parsed = JSON.parse(trimmed);
          const sanitizedChild = traverse(parsed, parentKey);
          return JSON.stringify(sanitizedChild);
        } catch (e) {
          // Fall through to regular text sanitization if not valid JSON
        }
      }

      // 2. Regular string sanitization
      const textSanitizeResult = sanitizeText(item, enabled);
      mergeResult(textSanitizeResult);
      let val = textSanitizeResult.sanitized;

      // 3. Key context validation: If the parent key is sensitive and the value wasn't redacted by regex
      // but contains potential credentials (and is not already the placeholder)
      if (
        parentKey &&
        isSensitiveKey(parentKey) &&
        val !== placeholder &&
        val.length > 0 &&
        enabled.generic
      ) {
        // Redact the whole string value if it looks like a credential (not a boolean/simple status/common words)
        const lowVal = val.toLowerCase();
        const nonSecrets = ['true', 'false', 'null', 'undefined', 'ok', 'success', 'application/json', 'bearer'];
        if (!nonSecrets.includes(lowVal) && val.length > 5) {
          stats.generic++;
          details.push({
            type: 'generic',
            originalSnippet: maskSecret(item),
            placeholder
          });
          val = placeholder;
        }
      }

      return val;
    }

    if (Array.isArray(item)) {
      return item.map(element => traverse(element, parentKey));
    }

    if (typeof item === 'object') {
      const sanitizedObj: any = {};
      for (const key of Object.keys(item)) {
        sanitizedObj[key] = traverse(item[key], key);
      }
      return sanitizedObj;
    }

    return item;
  }

  const sanitized = traverse(obj);

  return {
    sanitized,
    stats,
    details
  };
}
