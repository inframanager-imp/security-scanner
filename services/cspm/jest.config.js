module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // Transpile-only: full type-checking is done by `npm run typecheck` (per-cloud
  // tsc passes). Type-checking the 115-SDK import graph inside every Jest worker
  // needs ~5 GB per worker and OOM-crashes an 8 GB WSL VM.
  transform: {
    '^.+\\.ts$': ['ts-jest', { isolatedModules: true }],
  },
  maxWorkers: 2,
  roots: ['<rootDir>/tests', '<rootDir>/api/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/index.ts',
    'api/src/**/*.ts',
    '!api/src/**/*.d.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  testTimeout: 30000
};
