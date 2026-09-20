import http from "k6/http";
import { check, sleep } from "k6";

const apiUrl = __ENV.READINESS_API_URL || "http://api:8000";
const webUrl = __ENV.READINESS_WEB_URL || "http://web:3000";
if (apiUrl !== "http://api:8000" || webUrl !== "http://web:3000") {
  throw new Error("Readiness load tests are restricted to internal Compose services");
}

export const options = {
  scenarios: {
    local_readiness: {
      executor: "constant-vus",
      vus: Number(__ENV.READINESS_VUS || 10),
      duration: __ENV.READINESS_DURATION || "20s",
      gracefulStop: "5s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000"],
    checks: ["rate>0.99"],
  },
  userAgent: "CyberAudit-Readiness-k6/1.0",
};

export default function () {
  const responses = http.batch([
    ["GET", `${apiUrl}/health`, null, { tags: { endpoint: "health" } }],
    ["GET", `${apiUrl}/ready`, null, { tags: { endpoint: "readiness" } }],
    ["GET", `${webUrl}/login`, null, { tags: { endpoint: "login_page" } }],
  ]);
  check(responses[0], { "health is 200": (response) => response.status === 200 });
  check(responses[1], { "readiness is 200": (response) => response.status === 200 });
  check(responses[2], { "login page is 200": (response) => response.status === 200 });
  sleep(0.2);
}
