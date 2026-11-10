import { expect, it } from "vitest";
import { isPublicByDesign } from "../src/index.js";

/** Pages that exist to be reached without a session are not "answers without authentication". */
it("knows what every site publishes on purpose", () => {
  for (const p of ["/robots.txt", "/sitemap.xml", "/sitemap-index.xml", "/.well-known/security.txt", "/favicon.ico", "/manifest.json", "/login", "/es/login", "/en-us/sign-in", "/signup", "/register", "/forgot-password", "/auth/login", "/terminos-y-condiciones.html", "/politica-de-privacidad.html", "/privacy", "/terms-of-service", "/cookies.html", "/login?next=/dashboard"]) {
    expect(isPublicByDesign(p), p).toBe(true);
  }
});

it("still flags what may hide data or actions", () => {
  for (const p of ["/api/user", "/api/auth/login", "/dashboard", "/admin", "/api/my-ip", "/impersonate", "/onboarding", "/api/login-history", "/backup.sql", "/es/dashboard/login-logs", "/api/privacy/export", "/api/cookies", "/api/terms", "/v1/login", "/graphql"]) {
    expect(isPublicByDesign(p), p).toBe(false);
  }
});
