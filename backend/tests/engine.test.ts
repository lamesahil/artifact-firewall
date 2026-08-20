import { sanitizeText, sanitizeJson } from '../src/engine.js';

function runTests() {
  console.log('--- RUNNING SECRET DETECTION ENGINE TESTS ---');
  let passCount = 0;
  let failCount = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      console.log(`✅ PASS: ${message}`);
      passCount++;
    } else {
      console.error(`❌ FAIL: ${message}`);
      failCount++;
    }
  }

  // 1. Test JWT Sanitization
  const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const textWithJwt = `Here is my token: ${testJwt} - do not share it.`;
  const jwtResult = sanitizeText(textWithJwt);
  assert(jwtResult.sanitized.includes('[REDACTED_SECRET]'), 'JWT should be redacted');
  assert(!jwtResult.sanitized.includes(testJwt), 'Original JWT should not be present');
  assert(jwtResult.stats.jwt === 1, 'JWT count should be 1');

  // 2. Test AWS Key Sanitization
  const awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
  const textWithAws = `AWS_ACCESS_KEY_ID=${awsAccessKey}`;
  const awsResult = sanitizeText(textWithAws);
  assert(awsResult.sanitized.includes('[REDACTED_SECRET]'), 'AWS Access Key should be redacted');
  assert(awsResult.stats.aws === 1, 'AWS key count should be 1');

  // 3. Test Database URIs
  const pgUri = 'postgresql://db_user:my_db_password_123@host.remote.com:5432/mydb?sslmode=require';
  const mongoUri = 'mongodb+srv://admin:passWord123@cluster0.abcde.mongodb.net/my_collection?retryWrites=true&w=majority';
  const dbText = `DB_URL=${pgUri}\nMONGO_URL=${mongoUri}`;
  const dbResult = sanitizeText(dbText);
  assert(dbResult.stats.database === 2, 'Should find 2 database URIs');
  assert(!dbResult.sanitized.includes('my_db_password_123'), 'DB password should be removed');
  assert(!dbResult.sanitized.includes('passWord123'), 'Mongo password should be removed');

  // 4. Test Generic API Keys in Context
  const stripeKey = 'sk_test_mockstripekeyfortestingpurposesonly0';
  const googleKey = 'AIzaSyMockKeyForTestingPurposesOnly0000';
  const slackToken = 'xoxb-mock-token-for-testing-purposes-only-slack';
  const genericText = `stripe: ${stripeKey}\ngoogle: ${googleKey}\nslack: ${slackToken}`;
  const genericResult = sanitizeText(genericText);
  assert(genericResult.stats.generic === 3, 'Should find 3 generic/specific API keys');
  assert(!genericResult.sanitized.includes(stripeKey), 'Stripe key should be redacted');

  // 5. Test Context Assignment
  const contextText = `api_key = "some_secret_value_123"\nauthorization: Bearer my_special_bearer_token`;
  const contextResult = sanitizeText(contextText);
  assert(contextResult.stats.generic === 2, 'Should find 2 generic credentials in context');

  // 6. Test JSON & HAR Recursive Traversal
  const mockHar = {
    log: {
      version: '1.2',
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://api.github.com/graphql',
            headers: [
              { name: 'Authorization', value: `Bearer ${testJwt}` },
              { name: 'Content-Type', value: 'application/json' }
            ],
            postData: {
              mimeType: 'application/json',
              // Serialized JSON string containing an AWS access key inside a HAR body string
              text: JSON.stringify({
                query: 'mutation { updateToken }',
                variables: {
                  awsKey: awsAccessKey,
                  dbConn: pgUri
                }
              })
            }
          }
        }
      ]
    }
  };

  const jsonResult = sanitizeJson(mockHar);
  assert(jsonResult.stats.jwt === 1, 'Should find 1 JWT in HAR headers');
  assert(jsonResult.stats.aws === 1, 'Should find 1 AWS key inside nested stringified HAR body JSON');
  assert(jsonResult.stats.database === 1, 'Should find 1 DB URI inside nested stringified HAR body JSON');

  // Ensure JSON remains syntactically valid and traversable
  const sanitizedHar = jsonResult.sanitized;
  assert(sanitizedHar.log.entries[0].request.headers[0].value.includes('[REDACTED_SECRET]'), 'HAR Header Authorization should be redacted');
  
  // Verify deserialization of postData.text was successful and redacted
  const parsedPostData = JSON.parse(sanitizedHar.log.entries[0].request.postData.text);
  assert(parsedPostData.variables.awsKey === '[REDACTED_SECRET]', 'Nested AWS Key should be redacted');
  assert(parsedPostData.variables.dbConn === '[REDACTED_SECRET]', 'Nested DB URI should be redacted');

  console.log(`\n--- TEST SUMMARY: ${passCount} PASSED, ${failCount} FAILED ---`);
  if (failCount > 0) {
    process.exit(1);
  }
}

runTests();
