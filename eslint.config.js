// ESLint 9 flat config. eslint-plugin-security runs inside the linter the team
// already uses. In CI, an "error" fails the build; a "warn" is reported only.
// That split is the SAST threshold, set from measured precision (see the report).
const security = require('eslint-plugin-security');

module.exports = [
  security.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs' },
    rules: {
      // Promoted to error: precise on this codebase.
      'security/detect-child-process': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-non-literal-require': 'error',
      // Left at warn: noisy here (bound better-sqlite3 params, validated fs reads).
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-object-injection': 'warn',
    },
  },
  { ignores: ['node_modules/', 'coverage/', '*.db', 'tests/'] },
];
