const node = require("@lynkflow/config/jest/node");

/** @type {import('jest').Config} */
module.exports = {
  ...node,
  collectCoverageFrom: ["src/**/*.ts", "app.ts", "!src/**/*.d.ts", "!src/**/index.ts"],
};
