import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  transpilePackages: ["@cyberaudit/ui", "@cyberaudit/types"],
  ...(process.env.CYBERAUDIT_DESKTOP_BUILD === "1"
    ? { experimental: { isrFlushToDisk: false } }
    : {}),
};

export default nextConfig;
