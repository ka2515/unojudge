import bcrypt from "bcryptjs";

const pwd = process.argv[2];
if (!pwd) {
  console.log("用法：node make_hash.js 你的密碼");
  process.exit(1);
}
const hash = bcrypt.hashSync(pwd, 10);
console.log(hash);
