import node from "@lynkflow/config/eslint/node";

/**
 * Thin extends of the shared Node ESLint layer -- see tooling.md.
 * No React plugin: this is a backend service, no components.
 */
export default [
  ...node({
    tsconfigRootDir: import.meta.dirname,
  }),
];
