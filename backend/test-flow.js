// Full paper flow (upload -> approve -> unlock -> audit). Start the backend and run
// `npm run seed:admin` first, then: node test-flow.js
// Requires Node 18+ (built-in fetch / FormData / Blob).

require("dotenv").config();

const B = process.env.API || `http://localhost:${process.env.PORT || 5000}/api`;

let pass = 0;
let fail = 0;

const check = (name, cond, extra = "") => {
  cond ? pass++ : fail++;
  console.log(
    `${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  -> " + extra}`
  );
};

async function req(method, path, { token, json, form } = {}) {
  const headers = {};

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  let body;

  if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  if (form) {
    body = form;
  }

  const res = await fetch(B + path, {
    method,
    headers,
    body
  });

  const text = await res.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  return {
    status: res.status,
    data
  };
}

// Accounts used by the automated flow test.
// These are intentionally separate from the permanent demo accounts.
const PW = "Str0ng!Passw0rd#2026";

let adminToken;

async function adminLogin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    throw new Error(
      "Set ADMIN_EMAIL / ADMIN_PASSWORD in .env and run `npm run seed:admin` first."
    );
  }

  const r = await req("POST", "/auth/login", {
    json: {
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD
    }
  });

  if (r.status !== 200) {
    throw new Error(
      `admin login failed (${r.status}): ${JSON.stringify(r.data)}`
    );
  }

  adminToken = r.data.token;
}

async function makeUser(name, role) {
  // Create a unique temporary account for every test run.
  // This prevents collisions with the permanent demo accounts.
  const email = `flow-test-${name}-${Date.now()}@iiitkottayam.ac.in`;

  await req("POST", "/auth/signup", {
    json: {
      name,
      email,
      password: PW
    }
  });

  const list = await req("GET", "/admin/users", {
    token: adminToken
  });

  const u = list.data.users.find((x) => x.email === email);

  if (!u) {
    throw new Error(`signup failed for ${email}`);
  }

  const set = await req("PATCH", `/admin/users/${u.id}/role`, {
    token: adminToken,
    json: {
      role
    }
  });

  if (set.status !== 200) {
    throw new Error(
      `role assignment failed for ${name}: ${JSON.stringify(set.data)}`
    );
  }

  const r = await req("POST", "/auth/login", {
    json: {
      email,
      password: PW
    }
  });

  if (r.status !== 200) {
    throw new Error(
      `login failed for ${name}: ${JSON.stringify(r.data)}`
    );
  }

  return {
    token: r.data.token,
    id: r.data.user.id,
    email
  };
}

async function upload(
  setter,
  approvers,
  startOffsetMin,
  endOffsetMin,
  k = 2
) {
  const now = Date.now();

  const form = new FormData();

  form.append(
    "file",
    new Blob(["secret paper contents"]),
    "paper.txt"
  );

  form.append("title", "Math Midterm");
  form.append("k", String(k));

  form.append(
    "examStartTime",
    new Date(now + startOffsetMin * 60000).toISOString()
  );

  form.append(
    "examEndTime",
    new Date(now + endOffsetMin * 60000).toISOString()
  );

  form.append(
    "approverIds",
    JSON.stringify(approvers.map((a) => a.id))
  );

  return req("POST", "/papers", {
    token: setter.token,
    form
  });
}

(async () => {
  const health = await fetch(B + "/health")
    .then((r) => r.json())
    .catch(() => null);

  check(
    "server is up",
    !!health,
    "is the backend running on port 5000?"
  );

  if (!health) return;

  await adminLogin();

  const setter = await makeUser("setter1", "setter");
  const a1 = await makeUser("approver1", "approver");
  const a2 = await makeUser("approver2", "approver");
  const inv = await makeUser("invigilator1", "invigilator");

  check(
    "4 users signed up + logged in",
    setter.token && a1.token && a2.token && inv.token
  );

  // ---- auth / roles ----

  let r = await req("GET", "/auth/profile");

  check(
    "no token -> 401",
    r.status === 401,
    r.status
  );

  r = await req("GET", "/auth/setter-test", {
    token: a1.token
  });

  check(
    "approver on setter route -> 403",
    r.status === 403,
    r.status
  );

  r = await req("GET", "/auth/me", {
    token: setter.token
  });

  check(
    "/auth/me works",
    r.status === 200 && r.data.user?.role === "setter",
    r.status
  );

  // ---- upload (exam window includes now) ----

  const approvers = [a1, a2, inv];

  r = await upload(a1, approvers, -5, 60);

  check(
    "approver cannot upload -> 403",
    r.status === 403,
    r.status
  );

  r = await upload(setter, approvers, -5, 60);

  check(
    "setter upload -> 201",
    r.status === 201,
    JSON.stringify(r.data)
  );

  const pid = r.data.id;

  // ---- list + approver directory (used by the frontend) ----

  r = await req("GET", "/papers", {
    token: setter.token
  });

  check(
    "setter sees own paper in list",
    r.status === 200 &&
      r.data.papers?.some((x) => x.id === pid),
    JSON.stringify(r.data).slice(0, 120)
  );

  check(
    "list never leaks ciphertext",
    r.status === 200 &&
      !JSON.stringify(r.data).includes("ciphertext")
  );

  r = await req("GET", "/auth/approvers", {
    token: setter.token
  });

  check(
    "approver directory works",
    r.status === 200 &&
      r.data.users?.length >= 3,
    JSON.stringify(r.data).slice(0, 120)
  );

  // ---- unlock before approvals ----

  r = await req("POST", `/papers/${pid}/unlock`, {
    token: inv.token
  });

  check(
    "unlock w/o approvals -> 403",
    r.status === 403,
    r.status
  );

  // ---- approvals ----

  r = await req("POST", `/papers/${pid}/approve`, {
    token: setter.token
  });

  check(
    "non-approver approve -> 403",
    r.status === 403,
    r.status
  );

  r = await req("POST", `/papers/${pid}/approve`, {
    token: a1.token
  });

  check(
    "approver1 approves (1/2)",
    r.status === 200 &&
      r.data.approvalCount === 1,
    JSON.stringify(r.data)
  );

  r = await req("POST", `/papers/${pid}/approve`, {
    token: a1.token
  });

  check(
    "double approve -> 409",
    r.status === 409,
    r.status
  );

  r = await req("POST", `/papers/${pid}/unlock`, {
    token: inv.token
  });

  check(
    "unlock with 1/2 approvals -> 403",
    r.status === 403,
    r.status
  );

  r = await req("POST", `/papers/${pid}/approve`, {
    token: a2.token
  });

  check(
    "approver2 approves (2/2)",
    r.status === 200 &&
      r.data.meetsThreshold === true,
    JSON.stringify(r.data)
  );

  r = await req("GET", `/papers/${pid}/status`, {
    token: inv.token
  });

  check(
    "status shows threshold met",
    r.status === 200 &&
      r.data.meetsThreshold,
    JSON.stringify(r.data)
  );

  // ---- unlock ----

  r = await req("POST", `/papers/${pid}/unlock`, {
    token: a1.token
  });

  check(
    "non-invigilator unlock -> 403",
    r.status === 403,
    r.status
  );

  r = await req("POST", `/papers/${pid}/unlock`, {
    token: inv.token
  });

  check(
    "invigilator unlock returns original file",
    r.status === 200 &&
      r.data === "secret paper contents",
    `${r.status} ${JSON.stringify(r.data)}`
  );

  // ---- time lock ----

  let e = await upload(
    setter,
    approvers,
    60,
    120
  );

  await req(
    "POST",
    `/papers/${e.data.id}/approve`,
    { token: a1.token }
  );

  await req(
    "POST",
    `/papers/${e.data.id}/approve`,
    { token: a2.token }
  );

  r = await req(
    "POST",
    `/papers/${e.data.id}/unlock`,
    { token: inv.token }
  );

  check(
    "too early -> 403",
    r.status === 403 &&
      /not started/.test(r.data.message || ""),
    JSON.stringify(r.data)
  );

  // A window that has already closed can no longer be uploaded (validation) ...
  r = await upload(
    setter,
    approvers,
    -120,
    -60
  );

  check(
    "upload with past exam window -> 400",
    r.status === 400,
    `${r.status} ${JSON.stringify(r.data)}`
  );

  // ... so exercise "too late" with a window that closes shortly after approvals.
  const windowSeconds = 8;
  e = await upload(
    setter,
    approvers,
    -5,
    windowSeconds / 60
  );

  check(
    "short-window upload -> 201",
    e.status === 201,
    JSON.stringify(e.data)
  );

  const ap1 = await req(
    "POST",
    `/papers/${e.data.id}/approve`,
    { token: a1.token }
  );

  const ap2 = await req(
    "POST",
    `/papers/${e.data.id}/approve`,
    { token: a2.token }
  );

  const endTime = new Date(e.data.examEndTime).getTime();
  const waitMs = Math.max(1000, endTime - Date.now() + 1000);
  await new Promise((res) =>
    setTimeout(res, waitMs)
  );

  r = await req(
    "POST",
    `/papers/${e.data.id}/unlock`,
    { token: inv.token }
  );

  check(
    "too late -> 403",
    r.status === 403 &&
      /closed/.test(r.data.message || ""),
    JSON.stringify(r.data)
  );

  // ---- upload validation ----

  r = await upload(
    setter,
    [a1, a1],
    0,
    60
  );

  check(
    "duplicate approverIds -> 400",
    r.status === 400,
    `${r.status} ${JSON.stringify(r.data)}`
  );

  r = await upload(
    setter,
    [a1, { id: "64b0000000000000000000aa" }],
    0,
    60
  );

  check(
    "unknown approver id -> 400",
    r.status === 400,
    `${r.status} ${JSON.stringify(r.data)}`
  );

  r = await upload(
    setter,
    [a1, setter],
    0,
    60
  );

  check(
    "non-approver role as approver -> 400",
    r.status === 400,
    `${r.status} ${JSON.stringify(r.data)}`
  );

  r = await upload(
    setter,
    approvers,
    60,
    30
  );

  check(
    "end before start -> 400",
    r.status === 400,
    `${r.status} ${JSON.stringify(r.data)}`
  );

  {
    const big = new FormData();

    big.append(
      "file",
      new Blob([
        Buffer.alloc(16 * 1024 * 1024)
      ]),
      "big.bin"
    );

    big.append(
      "title",
      "Too big"
    );

    big.append(
      "examStartTime",
      new Date().toISOString()
    );

    big.append(
      "examEndTime",
      new Date(
        Date.now() + 3600000
      ).toISOString()
    );

    big.append(
      "approverIds",
      JSON.stringify(
        approvers.map((a) => a.id)
      )
    );

    r = await req(
      "POST",
      "/papers",
      {
        token: setter.token,
        form: big
      }
    );

    check(
      "oversized upload -> 413",
      r.status === 413,
      `${r.status} ${JSON.stringify(r.data)}`
    );
  }

  // ---- atomic approval: parallel double-approve ----

  e = await upload(
    setter,
    approvers,
    -5,
    60
  );

  const par = await Promise.all(
    [1, 2, 3, 4, 5].map(() =>
      req(
        "POST",
        `/papers/${e.data.id}/approve`,
        { token: a1.token }
      )
    )
  );

  const okCount = par.filter(
    (x) => x.status === 200
  ).length;

  check(
    "5 parallel approvals by one approver -> exactly one 200",
    okCount === 1,
    par.map((x) => x.status).join(",")
  );

  r = await req(
    "GET",
    `/papers/${e.data.id}/status`,
    { token: inv.token }
  );

  check(
    "...and approvalCount is 1",
    r.data.approvalCount === 1,
    JSON.stringify(r.data)
  );

  // ---- scoped reads ----

  const otherSetter = await makeUser(
    "setter2",
    "setter"
  );

  r = await req(
    "GET",
    `/papers/${e.data.id}/status`,
    { token: otherSetter.token }
  );

  check(
    "other setter cannot read paper status -> 404",
    r.status === 404,
    r.status
  );

  r = await req(
    "GET",
    "/audit?paperId=not-an-id",
    { token: inv.token }
  );

  check(
    "bad paperId filter -> 400",
    r.status === 400,
    r.status
  );

  r = await req(
    "GET",
    `/audit?paperId=${e.data.id}`,
    { token: otherSetter.token }
  );

  check(
    "other setter sees no audit entries for that paper",
    r.status === 200 &&
      r.data.length === 0,
    JSON.stringify(r.data).slice(0, 100)
  );

  r = await req(
    "GET",
    "/audit",
    { token: a1.token }
  );

  check(
    "approver audit view hides other users' emails",
    r.status === 200 &&
      (r.data || []).every(
        (x) =>
          !x.actor ||
          x.actor._id === a1.id ||
          !x.actor.email
      ),
    r.status
  );

  // ---- audit ----

  r = await req(
    "GET",
    "/audit",
    { token: inv.token }
  );

  check(
    "audit history returns entries",
    r.status === 200 &&
      Array.isArray(r.data) &&
      r.data.length > 0,
    r.status
  );

  const actions = new Set(
    (r.data || []).map((x) => x.action)
  );

  console.log(
    "      audit actions seen:",
    [...actions].join(", ")
  );

  r = await req(
    "GET",
    "/audit/verify",
    { token: inv.token }
  );

  console.log(
    "      audit verify result:",
    JSON.stringify(r.data)
  );

  check(
    "audit chain verify responds",
    r.status === 200,
    r.status
  );

  // ---- access token revoked on logout (tokenVersion) ----

  {
    // Use the SAME temporary setter account created by this test run.
    const lr = await fetch(
      B + "/auth/login",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email: setter.email,
          password: PW
        })
      }
    );

    const ld = await lr.json();

    const cookie = (
      lr.headers.get("set-cookie") || ""
    ).split(";")[0];

    let me = await req(
      "GET",
      "/auth/me",
      { token: ld.token }
    );

    check(
      "fresh access token works",
      me.status === 200,
      me.status
    );

    await fetch(
      B + "/auth/logout",
      {
        method: "POST",
        headers: {
          Cookie: cookie
        }
      }
    );

    me = await req(
      "GET",
      "/auth/me",
      { token: ld.token }
    );

    check(
      "access token rejected immediately after logout",
      me.status === 401,
      me.status
    );
  }

  console.log(
    `\n${pass} passed, ${fail} failed`
  );
})().catch((err) => {
  console.error(
    "Script error:",
    err
  );
  process.exit(1);
});