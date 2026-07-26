import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  transpilePackages: ["@cyberaudit/ui", "@cyberaudit/types"],
};

export default nextConfig;
