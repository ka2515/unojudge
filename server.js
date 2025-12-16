// pi5 v1.0
import fs from "node:fs";
import vm from "node:vm";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
//app.use(express.json({ limit: "1mb" }));

// === CORS（本機用；上線後建議改成你的網域）===
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ===== 可調參數 =====
const TIME_LIMIT_MS = 500;
const OUTPUT_LIMIT = 20000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_CLOUD_RUN";

// ===== 檔案讀寫（簡單安全）=====
function readJsonSafe(path, fallback) {
  try {
    if (!fs.existsSync(path)) return fallback;
    return JSON.parse(fs.readFileSync(path, "utf-8"));
  } catch {
    return fallback;
  }
}
function writeJsonSafe(path, obj) {
  fs.writeFileSync(path, JSON.stringify(obj, null, 2), "utf-8");
}

// ===== 題庫 =====
function loadBank(filePath = "tests_bank.json") {
  if (!fs.existsSync(filePath)) throw new Error(`tests bank not found: ${filePath}`);
  const bank = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const problems = bank?.problems;
  if (!Array.isArray(problems) || problems.length === 0) throw new Error("tests_bank.json format error");

  const map = new Map();
  for (const p of problems) {
    const id = String(p?.id || "").trim();
    const name = String(p?.name || id).trim();
    const tests = Array.isArray(p?.tests) ? p.tests : [];
    if (!id || tests.length === 0) continue;

    const normTests = tests.map((t, idx) => ({
      id: String(idx + 1).padStart(2, "0"),
      input: String(t?.in ?? ""),
      expected: String(t?.out ?? "")
    }));

    map.set(id, { id, name, tests: normTests });
  }
  if (map.size === 0) throw new Error("No valid problems in tests_bank.json");
  return map;
}
const BANK = loadBank("tests_bank.json");

// ===== 使用者 =====
const USERS_PATH = path.join(__dirname,"users.json");
function loadUsers() {
  const data = readJsonSafe(USERS_PATH, { users: [] });
  return Array.isArray(data.users) ? data.users : [];
}
function saveUsers(users) {
  writeJsonSafe(USERS_PATH, { users });
}

// ===== 作答紀錄（只存分數/耗時，不存作品）=====
const SUBMISSIONS_PATH = "submissions.json";
// 結構：{ "<email>": { "<problemId>": { pass, total, totalMs, updatedAt } } }
function loadSubs() {
  return readJsonSafe(SUBMISSIONS_PATH, {});
}
function saveSubs(obj) {
  writeJsonSafe(SUBMISSIONS_PATH, obj);
}

// ===== Auth =====
function signToken(user) {
  return jwt.sign(
    { email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "unauthorized" });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "unauthorized" });
  }
}

function adminRequired(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}

// ===== sandbox =====
function makeLineReader(inputText) {
  const lines = inputText.replace(/\r\n/g, "\n").split("\n");
  let p = 0;
  return () => (p < lines.length ? lines[p++] : "");
}

function normOutput(s) {
  const x = s.replace(/\r\n/g, "\n");
  return (
    x.split("\n").map(line => line.replace(/\s+$/g, "")).join("\n").trim() + "\n"
  );
}

function runUserJs(userJsCode, inputText, timeLimitMs = TIME_LIMIT_MS, outputLimit = OUTPUT_LIMIT) {
  const readLine = makeLineReader(inputText);
  let out = "";

  function print(x) {
    out += String(x) + "\n";
    if (out.length > outputLimit) throw new Error("OutputLimitExceeded");
  }

  const sandbox = {
    print,
    readLine,
    console: { log: print },
    window: { alert: print, prompt: () => readLine() }
  };

  const context = vm.createContext(sandbox);
  const wrapped = `"use strict";\n${userJsCode}\n`;
  const script = new vm.Script(wrapped, { filename: "student.js" });
  script.runInContext(context, { timeout: timeLimitMs });
  return out;
}

// ===== API =====

// 題目列表（給前端下拉）
app.get("/problems", (req, res) => {
  const list = [...BANK.values()].map(p => ({
    id: p.id,
    name: p.name,
    total: p.tests.length
  }));
  res.json({ problems: list });
});

// 登入 API：相容 email/username/account 三種欄位
app.post(["/login", "/api/login", "/auth/login"], async (req, res) => {
  try {
    const account =
      (req.body?.email ?? req.body?.username ?? req.body?.account ?? "").trim();
    const password = req.body?.password ?? "";

    if (!account || !password) {
      return res.status(400).json({ ok: false, error: "missing_credentials" });
    }

    // 讀 users.json（你目前的格式是 { users: [...] }）
    const data = readJsonSafe(USERS_PATH, { users: [] });
    const users = Array.isArray(data.users) ? data.users : [];

    // 用 email 或 username 比對（避免前端欄位差異）
    const user = users.find(
      (u) => u?.email === account || u?.username === account
    );

    if (!user) {
      return res.status(401).json({ ok: false, error: "user_not_found" });
    }

    // 支援 passwordHash（bcrypt）
    if (!user.passwordHash) {
      return res.status(500).json({ ok: false, error: "missing_password_hash" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ ok: false, error: "wrong_password" });
    }

    // ✅ 先做到「能登入」：回傳最小資訊
    return res.json({
      ok: true,
      role: user.role ?? "student",
      email: user.email ?? null,
      username: user.username ?? null,
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});






// 登入
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "missing email/password" });

  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "bad credentials" });

  const ok = bcrypt.compareSync(password, user.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "bad credentials" });

  const token = signToken(user);
  res.json({ token, email: user.email, role: user.role });
});

// 目前登入者
app.get("/auth/me", authRequired, (req, res) => {
  res.json({ email: req.user?.email ?? null, role: req.user?.role ?? "guest" });
});

// 使用者自行修改密碼：body { oldPassword, newPassword }
app.post("/auth/change-password", authRequired, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== "string" || typeof newPassword !== "string") {
    return res.status(400).json({ error: "missing oldPassword/newPassword" });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: "newPassword too short" });
  }

  const users = loadUsers();
  const email = req.user?.email;
  const u = email ? users.find(x => x.email === email) : null;

  if (!u) return res.status(404).json({ error: "user not found" });

  const ok = bcrypt.compareSync(oldPassword, u.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "bad credentials" });

  u.passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);

  res.json({ ok: true });
});

// 個人成績摘要（右側用）
app.get("/my/summary", (req, res) => {
  const subs = loadSubs();
  const mine = subs[req.user?.email ?? "__anonymous__"] || {};
  const problems = [...BANK.values()].map(p => {
    const r = mine[p.id];
    return {
      id: p.id,
      name: p.name,
      total: p.tests.length,
      pass: r?.pass ?? 0
    };
  });
  res.json({ problems });
});

// 評分（需要登入）
app.post("/grade", (req, res) => {
  const { code, problemId } = req.body || {};
  if (typeof code !== "string" || !code.trim()) return res.status(400).json({ error: "missing code" });
  if (typeof problemId !== "string" || !BANK.has(problemId)) return res.status(400).json({ error: "invalid problemId" });

  const problem = BANK.get(problemId);
  const TESTS = problem.tests;

  let pass = 0;
  let totalMs = 0;
  const results = [];

  for (const t of TESTS) {
    const t0 = process.hrtime.bigint();
    try {
      const got = runUserJs(code, t.input);
      const ok = normOutput(got) === normOutput(t.expected);
      if (ok) pass++;

      const t1 = process.hrtime.bigint();
      totalMs += Number(t1 - t0) / 1e6;

      results.push({ id: t.id, ok });
    } catch (e) {
      const t1 = process.hrtime.bigint();
      totalMs += Number(t1 - t0) / 1e6;

      results.push({ id: t.id, ok: false, error: String(e?.message || e) });
    }
  }

// ★ 新增：即使沒登入也不要炸（考場模式可用）
const email = (req.user && req.user.email) ? req.user.email : "__anonymous__";

// 存：只存分數/耗時（不存作品）
const subs = loadSubs();
subs[email] = subs[email] || {};
subs[email][problemId] = {
  pass,
  total: TESTS.length,
  totalMs: Math.round(totalMs * 1000) / 1000,
  updatedAt: new Date().toISOString()
};
saveSubs(subs);

res.json({
  problemId,
  problemName: problem.name,
  pass,
  total: TESTS.length,
  timeMs: Math.round(totalMs * 1000) / 1000,  // ★ 給前端用
  totalMs: Math.round(totalMs * 1000) / 1000, // ★ 保留舊欄位相容
  results
});
});


// ===== 管理者：使用者管理（你用）=====
app.get("/admin/users", authRequired, adminRequired, (req, res) => {
  const users = loadUsers().map(u => ({ email: u.email, role: u.role }));
  res.json({ users });
});

app.post("/admin/users", authRequired, adminRequired, (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "missing email/password" });

  const users = loadUsers();
  if (users.some(u => u.email === email)) return res.status(400).json({ error: "user exists" });

  const passwordHash = bcrypt.hashSync(password, 10);
  users.push({ email, passwordHash, role: role === "admin" ? "admin" : "user" });
  saveUsers(users);
  res.json({ ok: true });
});

app.put("/admin/users", authRequired, adminRequired, (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email) return res.status(400).json({ error: "missing email" });

  const users = loadUsers();
  const u = users.find(x => x.email === email);
  if (!u) return res.status(404).json({ error: "not found" });

  if (typeof password === "string" && password.length > 0) {
    u.passwordHash = bcrypt.hashSync(password, 10);
  }
  if (role) u.role = (role === "admin" ? "admin" : "user");

  saveUsers(users);
  res.json({ ok: true });
});

// 管理者全班概況（先提供 API，管理後台明天做）
app.get("/admin/overview", authRequired, adminRequired, (req, res) => {
  const subs = loadSubs();
  // 只回傳聚合資訊（不含作品）
  const overview = {};
  for (const p of BANK.values()) {
    overview[p.id] = { name: p.name, total: p.tests.length, students: 0, avgPass: 0 };
  }
  let countMap = {};
  let sumMap = {};
  for (const [email, m] of Object.entries(subs)) {
    for (const [pid, r] of Object.entries(m || {})) {
      if (!overview[pid]) continue;
      countMap[pid] = (countMap[pid] || 0) + 1;
      sumMap[pid] = (sumMap[pid] || 0) + (r.pass || 0);
    }
  }
  for (const pid of Object.keys(overview)) {
    const c = countMap[pid] || 0;
    const s = sumMap[pid] || 0;
    overview[pid].students = c;
    overview[pid].avgPass = c ? Math.round((s / c) * 100) / 100 : 0;
  }
  res.json({ overview });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "upload_grade.html"));
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Grader server running: http://localhost:${port}`);
  console.log(`Loaded problems: ${BANK.size}`);
});