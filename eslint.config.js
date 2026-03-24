'use strict';

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
        ...globals.es2020
      }
    },
    rules: {
      'no-var': 'error',
      'prefer-const': 'warn',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'eqeqeq': ['error', 'always'],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'strict': ['error', 'global'],
      'no-throw-literal': 'error',
      'no-self-compare': 'error',
      'no-template-curly-in-string': 'warn',
      'no-duplicate-imports': 'error',
      'no-promise-executor-return': 'warn',
      'no-constant-binary-expression': 'error',
      // Disabled — security scanner intentionally uses control chars and unicode patterns
      'no-control-regex': 'off',
      'no-misleading-character-class': 'off',
      'no-useless-assignment': 'off',
      'no-useless-escape': 'warn',
      'preserve-caught-error': 'off'
    }
  },
  {
    files: ['**/*.mjs'],
    languageOptions: {
      sourceType: 'module'
    },
    rules: {
      'strict': 'off'
    }
  },
  {
    files: ['test/**/*.js'],
    rules: {
      'no-unused-vars': 'off'
    }
  },
  {
    files: ['wasm/worker.js'],
    languageOptions: {
      sourceType: 'module'
    },
    rules: {
      'strict': 'off'
    }
  }
];
