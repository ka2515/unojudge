// 計算方塊版

import fs from "node:fs";
import vm from "node:vm";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// ===== 可調參數 =====
const TIME_LIMIT_MS = 500;
const OUTPUT_LIMIT = 20000;
const STEP_LIMIT = 200000; // ★B版：預設步數上限
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_CLOUD_RUN";

// ===== Session（考場最穩：cookie 維持登入態）=====
app.use(
  session({
    secret: process.env.SESSION_SECRET || "m5-offline-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // http 考場環境不要開 secure
    },
  })
);

// ===== CORS（若你同源使用，其實不需要；保留但支援 credentials）=====
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    // 不能用 "*" 搭配 credentials
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ===== 檔案讀寫（安全：原子寫入）=====
function readJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return fallback;
  }
}

function writeJsonSafeAtomic(filePath, obj) {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const tmp = path.join(dir, `.${base}.tmp`);
  const data = JSON.stringify(obj, null, 2);

  fs.writeFileSync(tmp, data, "utf-8");
  fs.renameSync(tmp, filePath);
}

// ===== 題庫 =====
function loadBank(filePath = path.join(__dirname, "tests_bank.json")) {
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
      expected: String(t?.out ?? ""),
    }));

    map.set(id, { id, name, tests: normTests });
  }
  if (map.size === 0) throw new Error("No valid problems in tests_bank.json");
  return map;
}

const BANK = loadBank();

// ===== 使用者 =====
const USERS_PATH = path.join(__dirname, "users.json");
function loadUsers() {
  const data = readJsonSafe(USERS_PATH, { users: [] });
  return Array.isArray(data.users) ? data.users : [];
}
function saveUsers(users) {
  writeJsonSafeAtomic(USERS_PATH, { users });
}

// ===== 作答紀錄（只存分數/步數，不存作品、不存耗時）=====
const SUBMISSIONS_PATH = path.join(__dirname, "submissions.json");
// 結構：{ "<email>": { "<problemId>": { pass, total, totalSteps, updatedAt } } }
function loadSubs() {
  return readJsonSafe(SUBMISSIONS_PATH, {});
}

// 寫入排隊（避免同時寫檔競態/互蓋/寫壞）
let subsWriteQueue = Promise.resolve();
function saveSubsQueued(obj) {
  subsWriteQueue = subsWriteQueue.then(() => {
    writeJsonSafeAtomic(SUBMISSIONS_PATH, obj);
  });
  return subsWriteQueue;
}

// ===== Auth（session-first；也支援 Bearer token 以保留相容性）=====
function signToken(user) {
  return jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
}

app.use((req, _res, next) => {
  if (req.session?.user) req.user = req.session.user;

  // ★重要：只要知道 email，就用 users.json 補齊 role/nickname（避免 session 快照過期）
  if (req.user?.email) {
    const users = loadUsers();
    const u = users.find((x) => x.email === req.user.email);
    req.user.role = u?.role ?? req.user.role ?? "user";
    req.user.nickname = u?.nickname ?? req.user.nickname ?? "";
  }

  next();
});


function authRequired(req, res, next) {
  // 1) session-first
  if (req.user?.email) return next();

  // 2) Bearer token
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "unauthorized" });

  try {
    const payload = jwt.verify(m[1], JWT_SECRET); // { email, role, ... }

    // ★補齊：以 users.json 為準
    const users = loadUsers();
    const u = users.find((x) => x.email === payload.email);

    req.user = {
      email: payload.email,
      role: u?.role ?? payload.role ?? "user",
      nickname: u?.nickname ?? "",
    };

    return next();
  } catch (e) {
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
    x
      .split("\n")
      .map((line) => line.replace(/\s+$/g, ""))
      .join("\n")
      .trim() + "\n"
  );
}

/**
 * runUserJs:
 * - Keep vm timeout (TIME_LIMIT_MS) for safety
 * - Keep OUTPUT_LIMIT
 * - ★ Add step counter: injected __tick() is called by Blockly STATEMENT_PREFIX
 * Returns: { out, execSteps }
 */
function runUserJs(userJsCode, inputText, timeLimitMs = TIME_LIMIT_MS, outputLimit = OUTPUT_LIMIT, stepLimit = STEP_LIMIT) {
  const readLine = makeLineReader(inputText);
  let out = "";

  function print(x) {
    out += String(x) + "\n";
    if (out.length > outputLimit) throw new Error("OutputLimitExceeded");
  }

  // ★B版：步數計數器（閉包內，學生較難竄改）
  let execSteps = 0;
  function __tick() {
    execSteps++;
    if (execSteps > stepLimit) throw new Error("__EXEC_STEP_LIMIT__");
  }

  const sandbox = {
    print,
    readLine,
    __tick, // ★B版：插樁後的學生程式會呼叫
    console: { log: print },
    window: { alert: print, prompt: () => readLine() },
  };

  const context = vm.createContext(sandbox);
  const wrapped = `"use strict";\n${userJsCode}\n`;
  const script = new vm.Script(wrapped, { filename: "student.js" });
  script.runInContext(context, { timeout: timeLimitMs });

  return { out, execSteps };
}

// ===== API =====

// 題目列表（給前端下拉）
app.get("/problems", (req, res) => {
  const list = [...BANK.values()].map((p) => ({
    id: p.id,
    name: p.name,
    total: p.tests.length,
  }));
  res.json({ problems: list });
});

// ✅ 統一登入（同時支援 /login /api/login /auth/login）
app.post(["/login", "/api/login", "/auth/login"], async (req, res) => {
  try {
    const account = (req.body?.email ?? req.body?.username ?? req.body?.account ?? "").trim();
    const password = req.body?.password ?? "";

    if (!account || !password) {
      return res.status(400).json({ ok: false, error: "missing_credentials" });
    }

    const users = loadUsers();
    const user = users.find((u) => u?.email === account || u?.username === account);

    if (!user) return res.status(401).json({ ok: false, error: "user_not_found" });
    if (!user.passwordHash) return res.status(500).json({ ok: false, error: "missing_password_hash" });
    if (!user.email) return res.status(500).json({ ok: false, error: "missing_email" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ ok: false, error: "wrong_password" });

    const role = user.role ?? "student";
    const nickname = user.nickname ?? "";

    req.session.user = { email: user.email, role, nickname };

    const token = signToken({ email: user.email, role });

    return res.json({
      ok: true,
      email: user.email,
      role,
      nickname,
      token,
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});


// 登出
app.post("/auth/logout", (req, res) => {
  req.session?.destroy?.(() => res.json({ ok: true }));
});

// 目前登入者
app.get("/auth/me", authRequired, (req, res) => {
  res.json({
    email: req.user?.email ?? null,
    role: req.user?.role ?? "guest",
    nickname: req.user?.nickname ?? "",
  });
});

// 使用者自行修改密碼：body { oldPassword, newPassword }
app.post("/auth/change-password", authRequired, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== "string" || typeof newPassword !== "string") {
    return res.status(400).json({ error: "missing oldPassword/newPassword" });
  }
  if (newPassword.length < 6) return res.status(400).json({ error: "newPassword too short" });

  const users = loadUsers();
  const email = req.user?.email;
  const u = email ? users.find((x) => x.email === email) : null;
  if (!u) return res.status(404).json({ error: "user not found" });

  const ok = bcrypt.compareSync(oldPassword, u.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "bad credentials" });

  u.passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);

  res.json({ ok: true });
});

// 使用者自行修改暱稱：body { nickname }
app.post("/auth/change-nickname", authRequired, (req, res) => {
  const { nickname } = req.body || {};
  if (typeof nickname !== "string") return res.status(400).json({ error: "missing nickname" });

  const nn = nickname.trim(); // 你要允許空白也行，就不要 trim 後檢查
  if (!nn) return res.status(400).json({ error: "nickname empty" });

  const users = loadUsers();
  const u = users.find((x) => x.email === req.user.email);
  if (!u) return res.status(404).json({ error: "user not found" });

  u.nickname = nn;
  saveUsers(users);

  // ★同步 session（如果使用者是 session 登入）
  if (req.session?.user) req.session.user.nickname = nn;

  res.json({ ok: true, nickname: nn });
});

// 個人成績摘要（右側用）
app.get("/my/summary", authRequired, (req, res) => {
  const subs = loadSubs();
  const mine = subs[req.user.email] || {};
  const problems = [...BANK.values()].map((p) => {
    const r = mine[p.id];
    return {
      id: p.id,
      name: p.name,
      total: p.tests.length,
      pass: r?.pass ?? 0,
    };
  });
  res.json({ problems });
});

// 評分（必須登入）
app.post("/grade", authRequired, async (req, res) => {
  const { code, problemId } = req.body || {};
  if (typeof code !== "string" || !code.trim()) return res.status(400).json({ error: "missing code" });
  if (typeof problemId !== "string" || !BANK.has(problemId)) return res.status(400).json({ error: "invalid problemId" });

  const problem = BANK.get(problemId);
  const TESTS = problem.tests;

  let pass = 0;
  let totalSteps = 0;
  const results = [];

  for (const t of TESTS) {
    try {
      const { out, execSteps } = runUserJs(code, t.input);
      totalSteps += execSteps;

      const ok = normOutput(out) === normOutput(t.expected);
      if (ok) pass++;

      // 回每 case 步數（教學更好；你若不想回可刪掉 execSteps）
      results.push({ id: t.id, ok, execSteps });
    } catch (e) {
      results.push({ id: t.id, ok: false, error: String(e?.message || e) });
    }
  }

  const email = req.user.email;

  // 存：只存分數/步數（不存作品、不存耗時）
  const subs = loadSubs();
  subs[email] = subs[email] || {};
  subs[email][problemId] = {
    pass,
    total: TESTS.length,
    totalSteps,
    updatedAt: new Date().toISOString(),
  };

  await saveSubsQueued(subs);

  res.json({
    problemId,
    problemName: problem.name,
    pass,
    total: TESTS.length,
    execSteps: totalSteps,
    results,
  });
});

// ===== 管理者：使用者管理 =====
app.get("/admin/users", authRequired, adminRequired, (req, res) => {
  const users = loadUsers().map((u) => ({
    email: u.email,
    role: u.role,
    nickname: u.nickname ?? "",
  }));
  res.json({ users });
});

app.post("/admin/users", authRequired, adminRequired, (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "missing email/password" });

  const users = loadUsers();
  if (users.some((u) => u.email === email)) return res.status(400).json({ error: "user exists" });

  const passwordHash = bcrypt.hashSync(password, 10);
  users.push({ email, passwordHash, role: role === "admin" ? "admin" : "user" });
  saveUsers(users);
  res.json({ ok: true });
});

app.put("/admin/users", authRequired, adminRequired, (req, res) => {
  const { email, password, role, nickname } = req.body || {}; // ★把 nickname 解構出來
  if (!email) return res.status(400).json({ error: "missing email" });

  const users = loadUsers();
  const u = users.find((x) => x.email === email);
  if (!u) return res.status(404).json({ error: "not found" });

  if (typeof password === "string" && password.length > 0) {
    u.passwordHash = bcrypt.hashSync(password, 10);
  }
  if (role) u.role = role === "admin" ? "admin" : "user";

  // ★寫入暱稱
  if (typeof nickname === "string") {
    u.nickname = nickname.trim();
  }

  saveUsers(users);
  res.json({ ok: true });
});


// 管理者全班概況
app.get("/admin/overview", authRequired, adminRequired, (req, res) => {
  const subs = loadSubs();
  const overview = {};
  for (const p of BANK.values()) {
    overview[p.id] = { name: p.name, total: p.tests.length, students: 0, avgPass: 0 };
  }

  const countMap = {};
  const sumMap = {};

  for (const [_email, m] of Object.entries(subs)) {
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

// 首頁
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "upload_grade.html"));
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Grader server running: http://localhost:${port}`);
  console.log(`Loaded problems: ${BANK.size}`);
  console.log(`TIME_LIMIT_MS=${TIME_LIMIT_MS} OUTPUT_LIMIT=${OUTPUT_LIMIT} STEP_LIMIT=${STEP_LIMIT}`);
});
