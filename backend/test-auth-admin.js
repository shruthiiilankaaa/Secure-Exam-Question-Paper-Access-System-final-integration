// Tests signup rules, pending accounts, admin role management and rate limiting.
// Start the backend first, run `npm run seed:admin` once, then:  node test-auth-admin.js
// Needs Node 18+. Reads ADMIN_EMAIL / ADMIN_PASSWORD (and PORT) from backend/.env.
require("dotenv").config();

const B = process.env.API || `http://localhost:${process.env.PORT || 5000}/api`;
const DOMAIN = "iiitkottayam.ac.in";
const PW = "Tr!cky-Passw0rd-42";
const run = Date.now().toString(36);
let pass = 0, fail = 0;

const check = (name, cond, extra = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  -> " + extra}`);
};

// Minimal cookie jar: Node's fetch doesn't persist Set-Cookie across calls,
// and the refresh flow depends on the httpOnly cookie round-tripping.
const jar = new Map();
function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res) {
  const raw = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : res.headers.raw?.()["set-cookie"] || [];
  for (const line of raw) {
    const [pair] = line.split(";");
    const eq = pair.indexOf("=");
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (/expires=Thu, 01 Jan 1970/i.test(line) || value === "") jar.delete(name);
    else jar.set(name, value);
  }
}

async function req(method, path, { token, json, raw, noCookie } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (!noCookie && jar.size) headers.Cookie = cookieHeader();
  let body;
  if (raw !== undefined) { headers["Content-Type"] = "application/json"; body = raw; }
  else if (json) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  const res = await fetch(B + path, { method, headers, body });
  storeCookies(res);
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}
function hasRefreshCookie() { return jar.has("refreshToken"); }
function clearJar() { jar.clear(); }

const signup = (email, password = PW, extra = {}) =>
  req("POST", "/auth/signup", { json: { name: "Test User", email, password, ...extra } });
const login = (email, password = PW) => req("POST", "/auth/login", { json: { email, password } });

(async () => {
  const health = await fetch(B + "/health").then((r) => r.json()).catch(() => null);
  check("server is up", !!health, "is the backend running?");
  if (!health) return;

  // ---------- signup: email rules ----------
  let r = await signup("someone@gmail.com");
  check("non-IIIT email rejected (400)", r.status === 400 && /iiitkottayam/.test(r.data.message), JSON.stringify(r.data));
  r = await signup(`x${run}@sub.${DOMAIN}`);
  check("subdomain email rejected", r.status === 400, r.status);
  r = await signup(`x${run}@${DOMAIN}.evil.com`);
  check("lookalike domain rejected", r.status === 400, r.status);
  r = await signup(`x${run}@${DOMAIN}@evil.com`);
  check("double-@ email rejected", r.status === 400, r.status);
  r = await signup("not-an-email");
  check("malformed email rejected", r.status === 400, r.status);

  // ---------- signup: password rules ----------
  const weak = [
    ["too short", "Ab1!xyz"],
    ["no uppercase", "tr!cky-passw0rd-42"],
    ["no lowercase", "TR!CKY-PASSW0RD-42"],
    ["no number", "Tr!cky-Password-xx"],
    ["no special char", "TrickyPassword42x"],
    ["over 72 bytes", "Aa1!" + "x".repeat(80)],
    ["contains email username", `Xx!${"weakuser" + run}9`],
  ];
  for (const [label, pw] of weak) {
    const email = label === "contains email username" ? `weakuser${run}@${DOMAIN}` : `pw${run}@${DOMAIN}`;
    r = await signup(email, pw);
    check(`weak password rejected: ${label}`, r.status === 400 && /Password/.test(r.data.message || ""), JSON.stringify(r.data));
  }

  // ---------- signup: input hardening ----------
  r = await req("POST", "/auth/signup", { raw: `{"name":"x","email":{"$ne":null},"password":"${PW}"}` });
  check("operator-object email -> 400 (not 500)", r.status === 400, r.status);
  r = await req("POST", "/auth/login", { raw: `{"email":{"$gt":""},"password":{"$gt":""}}` });
  check("operator-object login -> 400 (not 500)", r.status === 400, r.status);

  // ---------- signup: success = pending, role ignored ----------
  const email = `authtest-${run}@${DOMAIN}`;
  r = await signup(email, PW, { role: "admin" }); // try to sneak in a role
  check("signup ok (201)", r.status === 201, JSON.stringify(r.data));
  check("account is 'pending' even when role:'admin' is sent", r.data.user?.role === "pending", JSON.stringify(r.data));
  const userId = r.data.user?.id;
  r = await signup(email.toUpperCase());
  check("duplicate email (case-insensitive) -> 409", r.status === 409, r.status);

  // ---------- pending login ----------
  r = await login(email);
  check("pending user login -> 403 awaiting approval", r.status === 403 && /awaiting/i.test(r.data.message || ""), JSON.stringify(r.data));
  r = await login(email, "Wrong-Passw0rd!");
  check("wrong password stays generic 401 (no pending leak)", r.status === 401, r.status);

  // ---------- admin ----------
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    console.log("\nSet ADMIN_EMAIL / ADMIN_PASSWORD in .env and run `npm run seed:admin` to test the admin part.");
    console.log(`\n${pass} passed, ${fail} failed`);
    return;
  }
  r = await login(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD);
  check("admin can log in", r.status === 200 && r.data.user?.role === "admin", `${r.status} ${JSON.stringify(r.data)} (did you run npm run seed:admin?)`);
  if (r.status !== 200) { console.log(`\n${pass} passed, ${fail} failed`); return; }
  const admin = { token: r.data.token, id: r.data.user.id };

  r = await req("GET", "/admin/users");
  check("no token on /admin/users -> 401", r.status === 401, r.status);

  r = await req("GET", "/admin/users", { token: admin.token });
  const listed = r.data.users?.find((u) => u.id === userId);
  check("admin lists users incl. the new pending one", r.status === 200 && listed?.role === "pending", JSON.stringify(r.data).slice(0, 150));
  check("user list never leaks password hashes", !JSON.stringify(r.data).includes("passwordHash"));

  r = await req("PATCH", `/admin/users/${userId}/role`, { token: admin.token, json: { role: "admin" } });
  check("cannot grant 'admin' via API -> 400", r.status === 400, r.status);
  r = await req("PATCH", `/admin/users/${userId}/role`, { token: admin.token, json: { role: "pending" } });
  check("cannot set role back to 'pending' -> 400", r.status === 400, r.status);
  r = await req("PATCH", `/admin/users/not-an-id/role`, { token: admin.token, json: { role: "setter" } });
  check("bad user id -> 400", r.status === 400, r.status);
  r = await req("PATCH", `/admin/users/64b0000000000000000000aa/role`, { token: admin.token, json: { role: "setter" } });
  check("unknown user -> 404", r.status === 404, r.status);
  r = await req("PATCH", `/admin/users/${admin.id}/role`, { token: admin.token, json: { role: "setter" } });
  check("admin cannot change own role -> 403", r.status === 403, r.status);

  r = await req("PATCH", `/admin/users/${userId}/role`, { token: admin.token, json: { role: "setter" } });
  check("admin assigns 'setter' -> 200", r.status === 200 && r.data.user?.role === "setter", JSON.stringify(r.data));

  // ---------- new role works; non-admins blocked from admin routes ----------
  r = await login(email);
  check("user can now log in as setter", r.status === 200 && r.data.user?.role === "setter", JSON.stringify(r.data));
  const userToken = r.data.token;
  r = await req("GET", "/admin/users", { token: userToken });
  check("setter on /admin/users -> 403", r.status === 403, r.status);
  r = await req("PATCH", `/admin/users/${userId}/role`, { token: userToken, json: { role: "invigilator" } });
  check("setter cannot assign roles -> 403", r.status === 403, r.status);

  // ---------- role change applies immediately (no re-login) ----------
  r = await req("GET", "/auth/setter-test", { token: userToken });
  check("setter reaches setter-only route", r.status === 200, r.status);
  await req("PATCH", `/admin/users/${userId}/role`, { token: admin.token, json: { role: "approver" } });
  r = await req("GET", "/auth/setter-test", { token: userToken });
  check("after role change, OLD access token is revoked at once (401, tokenVersion)", r.status === 401, r.status);

  // ---------- audit ----------
  r = await req("GET", "/audit", { token: admin.token });
  const entry = Array.isArray(r.data) && r.data.find((e) => e.action === "ROLE_ASSIGNED" && e.details?.targetUserId === userId);
  check("ROLE_ASSIGNED recorded in audit log", !!entry, JSON.stringify(r.data).slice(0, 120));
  check("audit entry shows from -> to", entry && entry.details.to && entry.details.from, JSON.stringify(entry?.details));
  r = await req("GET", "/audit/verify", { token: admin.token });
  check("audit hash chain still valid", r.status === 200 && r.data.valid === true, JSON.stringify(r.data));

  // ---------- rate limiting (per IP + email) ----------
  const victim = `ratelimit-${run}@${DOMAIN}`;
  const statuses = [];
  for (let i = 0; i < 12; i++) statuses.push((await login(victim, "Wrong-Passw0rd!")).status);
  check("first 10 bad logins are plain 401s", statuses.slice(0, 10).every((s) => s === 401), statuses.join(","));
  check("11th bad login for same account -> 429", statuses[10] === 429, statuses.join(","));
  r = await login(email);
  check("other accounts are NOT locked out by that", r.status === 200, r.status);
  r = await login(victim, PW);
  check("locked account stays blocked even with any password", r.status === 429, r.status);

  // ---------- refresh token flow (needs a role-bearing user; admin block above created & set 'approver') ----------
  clearJar();
  r = await login(email, PW); // 'email' / 'userId' now has role "approver" from the admin section above
  check("login sets a refreshToken cookie", r.status === 200 && hasRefreshCookie());
  const firstAccessToken = r.data.token;
  const originalRefreshCookie = jar.get("refreshToken");

  r = await req("POST", "/auth/refresh");
  check("refresh with valid cookie -> 200 + new access token", r.status === 200 && r.data.token && r.data.token !== firstAccessToken, JSON.stringify(r.data).slice(0, 100));
  const secondAccessToken = r.data.token;
  const rotatedRefreshCookie = jar.get("refreshToken");
  check("refresh rotates the cookie to a new value", hasRefreshCookie() && rotatedRefreshCookie !== originalRefreshCookie);

  r = await req("GET", "/auth/me", { token: secondAccessToken });
  check("new access token works on a protected route", r.status === 200, r.status);

  r = await req("POST", "/auth/refresh", { noCookie: true });
  check("refresh with no cookie -> 401", r.status === 401, r.status);

  jar.set("refreshToken", originalRefreshCookie); // simulate a stolen/replayed pre-rotation cookie
  r = await req("POST", "/auth/refresh");
  check("reusing a rotated-away (pre-refresh) cookie -> 401", r.status === 401, JSON.stringify(r.data));
  jar.set("refreshToken", rotatedRefreshCookie); // restore the valid one

  // logout: clears cookie AND revokes via tokenVersion, so even a still-valid access token's future refresh dies
  clearJar();
  r = await login(email, PW);
  const accessBeforeLogout = r.data.token;
  r = await req("POST", "/auth/logout");
  check("logout clears the refresh cookie", r.status === 200 && !hasRefreshCookie(), r.status);
  r = await req("POST", "/auth/refresh");
  check("refresh after logout -> 401 (cookie gone)", r.status === 401, r.status);

  // access tokens now carry tokenVersion, so logout kills them immediately
  r = await req("GET", "/auth/me", { token: accessBeforeLogout });
  check("pre-logout access token is rejected right after logout (401)", r.status === 401, r.status);

  console.log(""); // spacer

  console.log(`\n${pass} passed, ${fail} failed`);
  console.log("(the rate-limit lock on the 'ratelimit-…' test email lasts 15 min; it uses a fresh email each run)");
})().catch((e) => { console.error("Script error:", e); process.exit(1); });
