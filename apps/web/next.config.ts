import type { NextConfig } from "next";

/**
 * The browser only ever talks to this origin. `/api/*` is proxied to the API service, so
 * session cookies stay first-party and the API needs no CORS (ADR-0008).
 */
const apiOrigin = process.env.SKYLINE_API_ORIGIN ?? "http://localhost:8000";

const securityHeaders = [
  // Baseline for every response, including ones the nonce proxy skips (prefetches, assets).
  // Browsers enforce both this and the per-page nonce policy.
  {
    key: "Content-Security-Policy",
    value: "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  // No server-side image optimisation: it needs sharp/libvips (LGPL), excluded by policy.
  images: { unoptimized: true },
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${apiOrigin}/api/v1/:path*` }];
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
