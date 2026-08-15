/**
 * One named constant every business route mount derives from --
 * see backend-conventions.md's "API versioning" section. /.well-known and
 * /health-style infrastructure endpoints are never versioned; every other
 * route mounts under /api/${API_VERSION}/....
 */
export const API_VERSION = "v1";
