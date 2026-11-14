// Runs before the app is imported in each security test. Points the app at a
// throwaway database and seeds it, so tests never touch real data and stay
// deterministic, regardless of order, the clock or the network.
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ci-test-secret-at-least-32-characters-long';
process.env.APP_DB = path.join(os.tmpdir(), `ca2-sec-${process.pid}-${Date.now()}.db`);

execSync('node seed.js', { cwd: path.join(__dirname, '..', '..'), env: process.env, stdio: 'ignore' });
