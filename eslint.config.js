'use strict';

const security = require('eslint-plugin-security');

/**
 * Flat ESLint config used both locally (`npm run lint`) and by the SAST job in
 * CI.  `eslint-plugin-security` adds rules for exactly the bug classes this lab
 * is about: dynamic code execution, non-literal fs/regex/require calls, object
 * injection and unsafe buffer handling.
 */
module.exports = [
  {
    ignores: ['node_modules/**', 'coverage/**', 'reports/**', 'data/**']
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'writable',
        exports: 'writable',
        process: 'readonly',
        console: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly'
      }
    },
    plugins: { security },
    rules: {
      ...security.configs.recommended.rules,
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-console': 'off',
      eqeqeq: ['error', 'smart'],
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    }
  }
];
