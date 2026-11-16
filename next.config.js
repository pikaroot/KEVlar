/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server bundle (.next/standalone) so the Docker image
  // ships only the files it needs to run `node server.js` — no dev deps, no
  // full node_modules. See the Dockerfile.
  output: "standalone",
};

module.exports = nextConfig;
