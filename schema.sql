/* ============================================================
   专注钓鱼 —— Cloudflare D1 数据库表结构
   ------------------------------------------------------------
   建库命令（只需执行一次）：
     npx wrangler d1 create focus-fishing-db
   然后把输出里的 database_id 填进 wrangler.toml。

   建表（本地 / 远程 二选一）：
     npx wrangler d1 execute focus-fishing-db --file=./schema.sql
     npx wrangler d1 execute focus-fishing-db --remote --file=./schema.sql

   注意：Pages Functions 需要在 Cloudflare 后台绑定 D1，
   变量名必须叫 DB（Settings → Functions → D1 database bindings）。
   ============================================================ */

/* 账号表：密码只存 PBKDF2 加盐哈希，绝不存明文 */
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL UNIQUE,
  pass_hash   TEXT    NOT NULL,          -- PBKDF2-SHA256, 100000 轮, hex
  pass_salt   TEXT    NOT NULL,          -- 16 字节随机盐, hex
  created_at  INTEGER NOT NULL
);

/* 存档表：data 是整个游戏存档的 JSON 文本。
   之所以用整块 JSON 而不是拆字段：后续加联机/排行榜等新数据时
   直接往 JSON 里加键即可，不需要改表结构、不需要迁移。 */
CREATE TABLE IF NOT EXISTS saves (
  user_id     INTEGER PRIMARY KEY,
  data        TEXT    NOT NULL,
  updated_at  INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

/* 会话表：登录 token（随机 32 字节 hex），带过期时间 */
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT    PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

/* ============================================================
   【联机阶段预留】以下是「实时多人同钓」才需要的表，
   现在先不启用，等你确认要做联机时再取消注释执行。
   ============================================================ */

-- CREATE TABLE IF NOT EXISTS rooms (
--   id          TEXT PRIMARY KEY,          -- 房间号
--   host_id     INTEGER NOT NULL,
--   loc         TEXT NOT NULL,             -- 钓点
--   created_at  INTEGER NOT NULL,
--   expires_at  INTEGER NOT NULL
-- );

-- CREATE TABLE IF NOT EXISTS room_players (
--   room_id     TEXT NOT NULL,
--   user_id     INTEGER NOT NULL,
--   username    TEXT NOT NULL,
--   joined_at   INTEGER NOT NULL,
--   last_seen   INTEGER NOT NULL,          -- 心跳：用于判断掉线
--   catches     INTEGER NOT NULL DEFAULT 0,
--   PRIMARY KEY (room_id, user_id)
-- );
