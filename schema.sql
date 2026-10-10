/* ============================================================
   专注钓鱼 —— Cloudflare D1 数据库表结构
   最新修改时间：2026-10-11 00:45
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
   联机前置：好友 / 通知 / 每日统计
   房间（rooms / room_players）也一并建好，联机阶段直接启用。
   ============================================================ */

/* 好友关系：互为两条记录（A→B 与 B→A）。starred 标记星标，last_interact 用于「最近互动」排序 */
CREATE TABLE IF NOT EXISTS friends (
  user_id       INTEGER NOT NULL,
  friend_id     INTEGER NOT NULL,
  starred       INTEGER NOT NULL DEFAULT 0,
  last_interact INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (user_id, friend_id),
  FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE
);

/* 好友申请：from_id 申请 to_id；未处理超 10 天由接口自动清理（Q8） */
CREATE TABLE IF NOT EXISTS friend_requests (
  from_id    INTEGER NOT NULL,
  to_id      INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (from_id, to_id),
  FOREIGN KEY (from_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (to_id)   REFERENCES users(id) ON DELETE CASCADE
);

/* 通知：好友申请 / 通过 / 被拒绝 / 被删除 各落一条，前端通知区读取 */
CREATE TABLE IF NOT EXISTS notifications (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  type       TEXT    NOT NULL,   -- friend_request | friend_accepted | request_rejected | friend_removed
  from_id    INTEGER,
  from_name  TEXT,
  read       INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read);

/* 每日统计：按用户 + 本地日期存当天专注分钟 / 鱼数 / 金币，供好友列表读取 */
CREATE TABLE IF NOT EXISTS daily_stats (
  user_id    INTEGER NOT NULL,
  date       TEXT    NOT NULL,   -- YYYY-MM-DD（玩家本地日期）
  focus_min  INTEGER NOT NULL DEFAULT 0,
  fish       INTEGER NOT NULL DEFAULT 0,
  coins      INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, date),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

/* 房间：code 为 6 位邀请码（对外），status: waiting | active | ended（联机阶段启用） */
CREATE TABLE IF NOT EXISTS rooms (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  code         TEXT    NOT NULL UNIQUE,
  host_id      INTEGER NOT NULL,
  status       TEXT    NOT NULL DEFAULT 'waiting',
  duration_min INTEGER NOT NULL DEFAULT 25,
  started_at   INTEGER,
  focus_end_at INTEGER,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rooms_code ON rooms(code);

/* 房间成员：role: owner | member（联机阶段启用） */
CREATE TABLE IF NOT EXISTS room_players (
  room_id   INTEGER NOT NULL,
  user_id   INTEGER NOT NULL,
  role      TEXT    NOT NULL DEFAULT 'member',
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id),
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)  REFERENCES users(id) ON DELETE CASCADE
);

/* 房间战报：一轮结束后每个人的渔获。
   round 用该轮的 focus_end_at 时间戳字符串标识，房主再来一轮时 round 自然变化；
   主键保证同一轮重复上报只是覆盖（幂等）。2026-10-11 新增，供结算弹窗展示。 */
CREATE TABLE IF NOT EXISTS room_results (
  room_id   INTEGER NOT NULL,
  round     TEXT    NOT NULL,
  user_id   INTEGER NOT NULL,
  fish_id   TEXT,
  fish_name TEXT,
  rarity    TEXT,
  weight    INTEGER NOT NULL DEFAULT 0,
  coins     INTEGER NOT NULL DEFAULT 0,
  focus_min INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, round, user_id),
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)  REFERENCES users(id) ON DELETE CASCADE
);
