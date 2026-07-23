import { defineConfig } from 'oxfmt';

export default defineConfig({
  singleQuote: true,
  ignorePatterns: ['pnpm-lock.yaml', 'LIEF'],
});
