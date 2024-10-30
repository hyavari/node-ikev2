import globals from 'globals'
import ts from 'typescript-eslint'
import tsParser from '@typescript-eslint/parser'
import eslintPrettierConfig from 'eslint-config-prettier'
import eslintPluginPrettier from 'eslint-plugin-prettier'

export default [
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
    languageOptions: {
      parser: tsParser,  // Use TypeScript ESLint parser
      globals: globals.node,
    },
    plugins: {
      prettier: eslintPluginPrettier,  // Add Prettier plugin
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',  // Disable no-explicit-any rule
    },
  },
  //...ts.configs.recommended,  // Use recommended TypeScript rules
  eslintPrettierConfig,  // Disable ESLint rules that conflict with Prettier
]
