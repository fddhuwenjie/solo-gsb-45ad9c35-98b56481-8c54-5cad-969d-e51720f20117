"""SQLite 持久层：主体密钥（含代次历史）、能力链及完整性报告。"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from .config import settings
from .models import (
    CapabilityToken,
    ChainSubmission,
    CoRedemptionEvent,
    IntegrityReport,
    KeyDeactivationEvent,
    QuotaStatus,
    RedemptionEvent,
    ReservationEvent,
    RevocationEvent,
    RevocationImpact,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    name               TEXT PRIMARY KEY,
    hmac_secret        TEXT NOT NULL,
    current_generation INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS chains (
    chain_id       TEXT PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    chain_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    token_json  TEXT NOT NULL,
    PRIMARY KEY (chain_id, position),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 主体 HMAC 密钥的完整代次历史（只追加）：注册为第 1 代，每次轮换追加一代并
-- 切换 principals.current_generation；旧代次永久保留，供轮换前提交的链重验。
CREATE TABLE IF NOT EXISTS principal_keys (
    principal    TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    hmac_secret  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (principal, generation),
    FOREIGN KEY (principal) REFERENCES principals (name)
);

-- 每条链在提交时锁定的“签发主体 -> 密钥代次”归属（随链写入，之后不可变）。
-- 链重放 / 求值 / 核销重验签名时按此归属取密钥：轮换不改变既有链的验签结论。
CREATE TABLE IF NOT EXISTS chain_key_generations (
    chain_id   TEXT NOT NULL,
    principal  TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (chain_id, principal),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 每条链在提交时“签发主体未注册、无法取得密钥”的事实（随链写入，之后不可变）。
-- 与 chain_key_generations 互补：归属表记录提交时已注册主体的代次，本表记录
-- 提交时未注册的主体。事后注册该主体（甚至轮换到匹配旧签名的密钥）都不会让
-- 旧链的 unknown_issuer 结论翻转。
CREATE TABLE IF NOT EXISTS chain_missing_issuers (
    chain_id   TEXT NOT NULL,
    principal  TEXT NOT NULL,
    PRIMARY KEY (chain_id, principal),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 疑似失陷密钥的停用事件（append-only，立即生效、不可撤销）。
-- 停用按（主体, 代次）唯一定位；后续轮换只追加新一代，绝不解除旧代次停用。
-- 链在求值 / 核销 / 会签中按各自提交时锁定的代次取钥时，命中停用即拒绝。
CREATE TABLE IF NOT EXISTS deactivated_keys (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    principal      TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    deactivated_at TEXT NOT NULL,
    UNIQUE (principal, generation),
    FOREIGN KEY (principal) REFERENCES principals (name)
);

-- 撤销事件为只追加（append-only）审计记录：无更新 / 删除路径。
-- request_key 全局唯一（跨链也不可复用）；同一令牌至多一条有效撤销事件。
CREATE TABLE IF NOT EXISTS revocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    effective_at   TEXT NOT NULL,
    reason         TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 撤销事件的影响清单：事件写入时在同一事务内算出并随事件保存，之后不可变。
-- 每行是一笔被追溯命中的成功核销（单链核销或会签的某一侧）；
-- 不改写 redemptions / co_redemptions 中的原核销记录。
CREATE TABLE IF NOT EXISTS revocation_impacts (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    revocation_request_key TEXT NOT NULL,
    access_request_key     TEXT NOT NULL,
    chain_id               TEXT NOT NULL,
    token_id               TEXT NOT NULL,
    kind                   TEXT NOT NULL,
    side                   TEXT,
    redeemed_at            TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    UNIQUE (revocation_request_key, access_request_key, chain_id, token_id),
    FOREIGN KEY (revocation_request_key) REFERENCES revocations (request_key)
);

-- 一次性访问核销：只在“末端 + 判定允许”时追加，成功后令牌不可再次核销。
-- request_key 全局唯一（重放/冲突判定）；同一链内同一令牌至多成功核销一次。
CREATE TABLE IF NOT EXISTS redemptions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    request_path   TEXT NOT NULL,
    method         TEXT NOT NULL,
    source_ip      TEXT,
    request_body   TEXT,
    content_sha256 TEXT NOT NULL,
    evaluated_at   TEXT NOT NULL,
    redeemed_at    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 双主体会签核销：主授权链与复核链的末端在同一事务内同时核销，或都不核销。
-- request_key 全局唯一（与单链核销共用同一键空间，由应用层交叉检查兜底）；
-- 每条链的末端令牌至多参与一次成功会签（含作为任一侧）。
CREATE TABLE IF NOT EXISTS co_redemptions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_key      TEXT NOT NULL UNIQUE,
    primary_chain_id TEXT NOT NULL,
    primary_token_id TEXT NOT NULL,
    review_chain_id  TEXT NOT NULL,
    review_token_id  TEXT NOT NULL,
    request_path     TEXT NOT NULL,
    method           TEXT NOT NULL,
    source_ip        TEXT,
    request_body     TEXT,
    content_sha256   TEXT NOT NULL,
    evaluated_at     TEXT NOT NULL,
    redeemed_at      TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    result_json      TEXT NOT NULL,
    UNIQUE (primary_chain_id, primary_token_id),
    UNIQUE (review_chain_id, review_token_id),
    FOREIGN KEY (primary_chain_id) REFERENCES chains (chain_id),
    FOREIGN KEY (review_chain_id) REFERENCES chains (chain_id)
);

-- 链末端 subject 的跨链成功核销总额度（一行一个主体；无行 = 未设置 = 不限额）。
-- 已用量不单独落库：始终由 redemptions（成功单链核销）与 co_redemptions
-- （会签中该主体参与的一侧，每笔对每个参与主体计一次）按当前末端 subject
-- 实时统计——天然包含额度设置之前的历史成功核销，且只追加的核销记录保证
-- 追溯撤销 / 密钥停用不退还历史用量、同键重放不重复计数。
-- limit 显式置 NULL 表示运维方主动清除额度（同样不限额，与未设置区分仅在 updated_at）。
CREATE TABLE IF NOT EXISTS redemption_quotas (
    subject    TEXT PRIMARY KEY,
    limit_value INTEGER,
    updated_at TEXT NOT NULL
);

-- 短时额度预留：为一次单链访问预先占一份额度（有效秒数 1～300，到期自动释放）。
-- reservation_key 全局唯一（仅有效预留占用；过期 / 转为核销后键即释放）；
-- 同一链内同一令牌至多一行——即同一令牌只能有一笔有效预留（过期行由应用层
-- 惰性清除后允许新预留）。预留不单独记已用：核销成功时同事务删除预留行，
-- 由 redemptions 计入已用量，份额从“预留”转为“已用”，可用量不变。
CREATE TABLE IF NOT EXISTS reservations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id        TEXT NOT NULL,
    token_id        TEXT NOT NULL,
    reservation_key TEXT NOT NULL UNIQUE,
    subject         TEXT NOT NULL,
    request_path    TEXT NOT NULL,
    method          TEXT NOT NULL,
    source_ip       TEXT,
    request_body    TEXT,
    content_sha256  TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);
"""

DEMO_PRINCIPALS = {
    "root": settings.root_hmac_secret,
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
    "alice": "demo-secret-alice",
}


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # 并发写事务（BEGIN IMMEDIATE）锁竞争时等待而非立刻 SQLITE_BUSY
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI 依赖：每请求一个连接，自动提交 / 回滚。"""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate_principals(conn)
    if settings.seed_demo_principals:
        conn.executemany(
            "INSERT OR IGNORE INTO principals (name, hmac_secret) VALUES (?, ?)",
            list(DEMO_PRINCIPALS.items()),
        )
    _backfill_key_tables(conn)
    conn.commit()


def _migrate_principals(conn: sqlite3.Connection) -> None:
    """为轮换功能上线前创建的既有库补充 current_generation 列（已有数据归一到第 1 代）。"""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(principals)")}
    if "current_generation" not in cols:
        conn.execute(
            "ALTER TABLE principals "
            "ADD COLUMN current_generation INTEGER NOT NULL DEFAULT 1"
        )


def _backfill_key_tables(conn: sqlite3.Connection) -> None:
    """把轮换功能上线前的数据归一到第 1 代密钥（幂等，可每次启动执行）。

    - 尚无密钥历史的主体：以其当前 hmac_secret 作为第 1 代（轮换过的主体已有
      历史行，INSERT OR IGNORE 自然跳过，不会用当前密钥覆盖旧代次）；
    - 既有链的密钥归属回填见 :func:`_backfill_chain_attributions`。
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO principal_keys "
        "(principal, generation, hmac_secret, created_at) "
        "SELECT name, 1, hmac_secret, ? FROM principals",
        (now,),
    )
    _backfill_chain_attributions(conn)


def _backfill_chain_attributions(conn: sqlite3.Connection) -> None:
    """回填既有链的“提交时密钥归属”（幂等，可每次启动执行）。

    以随链保存的提交时完整性报告为准区分两类签发者：

    - 报告中含 ``unknown_issuer`` 失败的主体：提交时未注册。把缺失事实记入
      ``chain_missing_issuers``，并清除早期版本误写入的代次归属——绝不把
      提交时未注册的签发者归到后来注册的密钥代次；
    - 其余签发者：提交时已注册（轮换功能上线前只有一代密钥），归属到第 1 代，
      原本有效的旧链继续按该历史密钥验签。
    """
    chains = conn.execute("SELECT chain_id, report_json FROM chains").fetchall()
    if not chains:
        return
    issuers_by_chain: dict[str, set[str]] = {}
    for row in conn.execute(
        "SELECT DISTINCT chain_id, "
        "json_extract(token_json, '$.issuer') AS issuer FROM tokens"
    ).fetchall():
        issuers_by_chain.setdefault(row["chain_id"], set()).add(row["issuer"])
    registered = {
        row["name"] for row in conn.execute("SELECT name FROM principals").fetchall()
    }
    for chain in chains:
        chain_id = chain["chain_id"]
        unknown = _report_unknown_issuers(chain["report_json"])
        for name in sorted(unknown):
            conn.execute(
                "DELETE FROM chain_key_generations "
                "WHERE chain_id = ? AND principal = ?",
                (chain_id, name),
            )
            conn.execute(
                "INSERT OR IGNORE INTO chain_missing_issuers (chain_id, principal) "
                "VALUES (?, ?)",
                (chain_id, name),
            )
        for name in sorted(issuers_by_chain.get(chain_id, set()) - unknown):
            if name in registered:
                conn.execute(
                    "INSERT OR IGNORE INTO chain_key_generations "
                    "(chain_id, principal, generation) VALUES (?, ?, 1)",
                    (chain_id, name),
                )


def _report_unknown_issuers(report_json: str) -> set[str]:
    """从随链保存的提交时报告中提取验签时未注册的签发者（解析失败按空集处理）。"""
    try:
        report = json.loads(report_json)
    except ValueError:
        return set()
    if not isinstance(report, dict):
        return set()
    unknown: set[str] = set()
    for node in report.get("trace") or []:
        if not isinstance(node, dict):
            continue
        for check in node.get("checks") or []:
            if not isinstance(check, dict):
                continue
            if check.get("reason") == "unknown_issuer" and not check.get("passed", True):
                issuer = node.get("issuer")
                if isinstance(issuer, str) and issuer:
                    unknown.add(issuer)
    return unknown


def get_secret(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute(
        "SELECT hmac_secret FROM principals WHERE name = ?", (name,)
    ).fetchone()
    return row["hmac_secret"] if row else None


def upsert_principal(conn: sqlite3.Connection, name: str, secret: str) -> bool:
    """注册主体并安装其第 1 代密钥（同一事务）；已存在返回 False。"""
    cur = conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES (?, ?)",
        (name, secret),
    )
    if cur.rowcount == 1:
        conn.execute(
            "INSERT INTO principal_keys "
            "(principal, generation, hmac_secret, created_at) "
            "VALUES (?, 1, ?, ?)",
            (name, secret, datetime.now(timezone.utc).isoformat()),
        )
    return cur.rowcount == 1


# --------------------------------------------------------------------------- #
# 密钥代次：当前快照、按代次取钥、原子轮换
# --------------------------------------------------------------------------- #
def get_principal_key_row(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    """主体的当前密钥行（name / hmac_secret / current_generation）；不存在返回 None。"""
    return conn.execute(
        "SELECT name, hmac_secret, current_generation FROM principals WHERE name = ?",
        (name,),
    ).fetchone()


def install_next_key_generation(
    conn: sqlite3.Connection, name: str, new_secret: str
) -> tuple[int, datetime]:
    """为主体安装新一代密钥并切换为当前代，返回 (新代次, 安装时间)。

    历史追加与当前代切换在同一事务内提交；调用方负责开启写事务
    （``BEGIN IMMEDIATE``）并在失败时回滚——任何失败都不会留下部分切换。
    """
    row = get_principal_key_row(conn, name)
    assert row is not None, "install_next_key_generation 前须确认主体存在"
    new_generation = row["current_generation"] + 1
    now = datetime.now(timezone.utc)
    conn.execute(
        "INSERT INTO principal_keys "
        "(principal, generation, hmac_secret, created_at) VALUES (?, ?, ?, ?)",
        (name, new_generation, new_secret, now.isoformat()),
    )
    conn.execute(
        "UPDATE principals SET hmac_secret = ?, current_generation = ? WHERE name = ?",
        (new_secret, new_generation, name),
    )
    return new_generation, now


def snapshot_current_keys(
    conn: sqlite3.Connection, names: Iterable[str]
) -> dict[str, tuple[str, int]]:
    """当前密钥快照：``{主体名: (密钥, 代次)}``；未注册主体不出现在结果中。

    链提交时先取快照再验签、再把快照中的代次随链持久化，保证与并发轮换
    交错时“验签用哪一代密钥，归属就记哪一代”。
    """
    unique = sorted(set(names))
    if not unique:
        return {}
    placeholders = ", ".join("?" for _ in unique)
    rows = conn.execute(
        "SELECT name, hmac_secret, current_generation FROM principals "
        f"WHERE name IN ({placeholders})",
        unique,
    ).fetchall()
    return {r["name"]: (r["hmac_secret"], r["current_generation"]) for r in rows}


def get_secret_at_generation(
    conn: sqlite3.Connection, name: str, generation: int
) -> str | None:
    """指定代次的密钥；主体或该代次不存在时返回 None。"""
    row = conn.execute(
        "SELECT hmac_secret FROM principal_keys "
        "WHERE principal = ? AND generation = ?",
        (name, generation),
    ).fetchone()
    return row["hmac_secret"] if row else None


# --------------------------------------------------------------------------- #
# 疑似失陷密钥停用（按主体名 + 代次；立即生效、不可撤销，轮换不解除）
# --------------------------------------------------------------------------- #
def key_generation_exists(
    conn: sqlite3.Connection, name: str, generation: int
) -> bool:
    """主体是否存在且拥有指定代次的密钥（未注册主体或越界代次均为 False）。"""
    row = conn.execute(
        "SELECT 1 FROM principal_keys WHERE principal = ? AND generation = ?",
        (name, generation),
    ).fetchone()
    return row is not None


def load_key_deactivation(
    conn: sqlite3.Connection, name: str, generation: int
) -> KeyDeactivationEvent | None:
    """某主体某代次密钥的停用事件；未停用（或主体 / 代次不存在）时返回 None。"""
    row = conn.execute(
        "SELECT principal, generation, reason, deactivated_at "
        "FROM deactivated_keys WHERE principal = ? AND generation = ?",
        (name, generation),
    ).fetchone()
    return _key_deactivation_from_row(row) if row else None


def load_deactivated_keys(
    conn: sqlite3.Connection,
) -> dict[tuple[str, int], KeyDeactivationEvent]:
    """当前已停用的 ``{(主体, 代次): 停用事件}`` 快照。

    单次读取整表：求值 / 核销 / 会签在同一事务内据此判定，保证与并发停用
    交错时，一条链上的各签发节点对应同一份已提交（已停用）状态。
    """
    rows = conn.execute(
        "SELECT principal, generation, reason, deactivated_at FROM deactivated_keys"
    ).fetchall()
    return {
        (r["principal"], r["generation"]): _key_deactivation_from_row(r) for r in rows
    }


def insert_key_deactivation(
    conn: sqlite3.Connection, event: KeyDeactivationEvent
) -> None:
    """追加一条密钥停用事件；同一（主体, 代次）重复停用时抛 IntegrityError。"""
    conn.execute(
        "INSERT INTO deactivated_keys (principal, generation, reason, deactivated_at) "
        "VALUES (?, ?, ?, ?)",
        (
            event.principal,
            event.generation,
            event.reason,
            event.deactivated_at.astimezone(timezone.utc).isoformat(),
        ),
    )


def _key_deactivation_from_row(row: sqlite3.Row) -> KeyDeactivationEvent:
    return KeyDeactivationEvent(
        principal=row["principal"],
        generation=row["generation"],
        reason=row["reason"],
        deactivated_at=datetime.fromisoformat(row["deactivated_at"]),
    )


def load_chain_key_generations(
    conn: sqlite3.Connection, chain_id: str
) -> dict[str, int]:
    """链在提交时锁定的 ``{签发主体: 密钥代次}`` 归属（无记录时为空 dict）。"""
    rows = conn.execute(
        "SELECT principal, generation FROM chain_key_generations WHERE chain_id = ?",
        (chain_id,),
    ).fetchall()
    return {r["principal"]: r["generation"] for r in rows}


def load_chain_missing_issuers(
    conn: sqlite3.Connection, chain_id: str
) -> set[str]:
    """链在提交时未注册（无法取得密钥）的签发主体集合（无记录时为空集）。"""
    rows = conn.execute(
        "SELECT principal FROM chain_missing_issuers WHERE chain_id = ?",
        (chain_id,),
    ).fetchall()
    return {r["principal"] for r in rows}


def save_chain(
    conn: sqlite3.Connection,
    submission: ChainSubmission,
    content_sha256: str,
    report: IntegrityReport,
    key_generations: dict[str, int],
    missing_issuers: Iterable[str] = (),
) -> None:
    """持久化链及其提交时锁定的密钥归属（同一事务，要么全部落库要么都不落）。

    ``key_generations`` 记录提交时已注册主体的密钥代次；``missing_issuers``
    记录提交时未注册的主体——“提交时缺失密钥”这一事实随链保存，事后注册
    不改变旧链的验签结论。
    """
    created_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            submission.chain_id,
            content_sha256,
            json.dumps(report.model_dump(mode="json"), ensure_ascii=False),
            created_at,
        ),
    )
    conn.executemany(
        "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
        [
            (submission.chain_id, i, t.model_dump_json())
            for i, t in enumerate(submission.tokens)
        ],
    )
    conn.executemany(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES (?, ?, ?)",
        [
            (submission.chain_id, name, generation)
            for name, generation in sorted(key_generations.items())
        ],
    )
    conn.executemany(
        "INSERT INTO chain_missing_issuers (chain_id, principal) VALUES (?, ?)",
        [(submission.chain_id, name) for name in sorted(missing_issuers)],
    )


def get_chain_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


def load_submission(conn: sqlite3.Connection, chain_id: str) -> ChainSubmission | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    rows = conn.execute(
        "SELECT token_json FROM tokens WHERE chain_id = ? ORDER BY position",
        (chain_id,),
    ).fetchall()
    tokens = [CapabilityToken.model_validate_json(r["token_json"]) for r in rows]
    return ChainSubmission(chain_id=chain_id, tokens=tokens)


def load_chain_record(conn: sqlite3.Connection, chain_id: str) -> dict | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    submission = load_submission(conn, chain_id)
    assert submission is not None
    return {
        "chain_id": chain_id,
        "content_sha256": chain["content_sha256"],
        "created_at": datetime.fromisoformat(chain["created_at"]),
        "integrity": IntegrityReport.model_validate(json.loads(chain["report_json"])),
        "tokens": submission.tokens,
        "revocations": load_revocations(conn, chain_id),
        "redemptions": load_redemptions(conn, chain_id),
    }


# --------------------------------------------------------------------------- #
# 撤销事件（不可变，只追加）
# --------------------------------------------------------------------------- #
def token_exists(conn: sqlite3.Connection, chain_id: str, token_id: str) -> bool:
    """令牌是否存在于指定链的提交中（按 position 存在性判定，重复 id 也算存在）。"""
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE chain_id = ? "
        "AND json_extract(token_json, '$.token_id') = ? LIMIT 1",
        (chain_id, token_id),
    ).fetchone()
    return row is not None


def load_revocation_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocation_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocations(
    conn: sqlite3.Connection, chain_id: str
) -> list[RevocationEvent]:
    """按追加顺序（id 升序）返回某条链的全部撤销事件。"""
    rows = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_revocation_from_row(r) for r in rows]


def insert_revocation(
    conn: sqlite3.Connection,
    event: RevocationEvent,
) -> None:
    """追加一条撤销事件；唯一约束冲突时抛出 sqlite3.IntegrityError（事务回滚）。"""
    conn.execute(
        "INSERT INTO revocations (chain_id, token_id, effective_at, reason, "
        "request_key, content_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.effective_at.astimezone(timezone.utc).isoformat(),
            event.reason,
            event.request_key,
            event.content_sha256,
            event.created_at.astimezone(timezone.utc).isoformat(),
        ),
    )


def _revocation_from_row(row: sqlite3.Row) -> RevocationEvent:
    return RevocationEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        effective_at=datetime.fromisoformat(row["effective_at"]),
        reason=row["reason"],
        request_key=row["request_key"],
        content_sha256=row["content_sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 一次性访问核销（只在允许且末端时追加，成功记录不可变）
# --------------------------------------------------------------------------- #
_REDEMPTION_COLUMNS = (
    "chain_id, token_id, request_key, request_path, method, source_ip, "
    "request_body, content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[RedemptionEvent, str] | None:
    """返回（核销事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _redemption_from_row(row), row["result_json"]


def load_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RedemptionEvent | None:
    """该令牌此前的成功核销记录（同一令牌只能成功核销一次）。

    单链核销与会签核销共用同一“已核销”判定：会签成功的每一侧，对单链
    核销而言同样视为已核销（反之亦然）——会签的一半不能被当作独立请求
    再次核销。
    """
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    if row is not None:
        return _redemption_from_row(row)
    co = load_co_redemption_for_token(conn, chain_id, token_id)
    if co is None:
        return None
    return co.leg_event(chain_id)


def load_redemptions(
    conn: sqlite3.Connection, chain_id: str
) -> list[RedemptionEvent]:
    """某条链的全部成功核销记录（单链核销 + 会签中涉及本链的一侧），按落库顺序。"""
    rows = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS} FROM redemptions "
        "WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    events = [_redemption_from_row(r) for r in rows]
    co_rows = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS} FROM co_redemptions "
        "WHERE primary_chain_id = ? OR review_chain_id = ?",
        (chain_id, chain_id),
    ).fetchall()
    events.extend(
        _co_redemption_from_row(r).leg_event(chain_id) for r in co_rows
    )
    # 两张表各自只追加；以落库时间（微秒级）归并排序，键与令牌 id 兜底确定性
    events.sort(key=lambda e: (e.created_at, e.request_key, e.token_id))
    return events


def insert_redemption(
    conn: sqlite3.Connection, event: RedemptionEvent, result_json: str
) -> None:
    """追加一条成功核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO redemptions (chain_id, token_id, request_key, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, redeemed_at, "
        "created_at, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.request_key,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _redemption_from_row(row: sqlite3.Row) -> RedemptionEvent:
    return RedemptionEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        request_key=row["request_key"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 双主体会签核销（两侧同时成功才追加，记录不可变）
# --------------------------------------------------------------------------- #
_CO_REDEMPTION_COLUMNS = (
    "request_key, primary_chain_id, primary_token_id, review_chain_id, "
    "review_token_id, request_path, method, source_ip, request_body, "
    "content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_co_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[CoRedemptionEvent, str] | None:
    """返回（会签事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS}, result_json FROM co_redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _co_redemption_from_row(row), row["result_json"]


def load_co_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> CoRedemptionEvent | None:
    """该令牌作为会签一侧（主或复核）此前的成功会签记录。"""
    row = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS} FROM co_redemptions "
        "WHERE (primary_chain_id = ? AND primary_token_id = ?) "
        "OR (review_chain_id = ? AND review_token_id = ?)",
        (chain_id, token_id, chain_id, token_id),
    ).fetchone()
    return _co_redemption_from_row(row) if row else None


def insert_co_redemption(
    conn: sqlite3.Connection, event: CoRedemptionEvent, result_json: str
) -> None:
    """追加一条会签核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO co_redemptions (request_key, primary_chain_id, "
        "primary_token_id, review_chain_id, review_token_id, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, "
        "redeemed_at, created_at, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.request_key,
            event.primary_chain_id,
            event.primary_token_id,
            event.review_chain_id,
            event.review_token_id,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _co_redemption_from_row(row: sqlite3.Row) -> CoRedemptionEvent:
    return CoRedemptionEvent(
        request_key=row["request_key"],
        primary_chain_id=row["primary_chain_id"],
        primary_token_id=row["primary_token_id"],
        review_chain_id=row["review_chain_id"],
        review_token_id=row["review_token_id"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 撤销影响清单（随撤销事件在同一事务内计算并保存，之后不可变）
# --------------------------------------------------------------------------- #
def compute_revocation_impacts(
    conn: sqlite3.Connection,
    event: RevocationEvent,
    affected_ids: Iterable[str],
) -> list[RevocationImpact]:
    """找出被撤销事件追溯命中的成功核销（单链核销与双主体会签均纳入）。

    命中条件（在事件写入的同一事务内对当前快照判定）：

    - 核销时间不早于 ``event.effective_at``，且早于事件写入时间
      ``event.created_at``；
    - 被核销的末端令牌是撤销目标或其后代（``affected_ids``）。

    一笔会签只列一次：按受影响的链投影出主授权 / 复核侧（两侧分属不同链，
    一次撤销至多命中其中一侧）；只读取原核销记录，不做任何改写。
    结果按 (核销时间, 访问 request_key) 升序。
    """
    affected = set(affected_ids)
    impacts: list[RevocationImpact] = []

    def _active(redeemed_at: datetime) -> bool:
        return event.effective_at <= redeemed_at < event.created_at

    rows = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS} FROM redemptions WHERE chain_id = ?",
        (event.chain_id,),
    ).fetchall()
    for row in rows:
        ev = _redemption_from_row(row)
        if ev.token_id not in affected or not _active(ev.redeemed_at):
            continue
        impacts.append(
            RevocationImpact(
                request_key=ev.request_key,
                chain_id=ev.chain_id,
                token_id=ev.token_id,
                kind="single",
                side=None,
                redeemed_at=ev.redeemed_at,
            )
        )

    co_rows = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS} FROM co_redemptions "
        "WHERE primary_chain_id = ? OR review_chain_id = ?",
        (event.chain_id, event.chain_id),
    ).fetchall()
    for row in co_rows:
        co = _co_redemption_from_row(row)
        if co.primary_chain_id == event.chain_id and co.primary_token_id in affected:
            side, token_id = "primary", co.primary_token_id
        elif co.review_chain_id == event.chain_id and co.review_token_id in affected:
            side, token_id = "review", co.review_token_id
        else:
            continue
        if not _active(co.redeemed_at):
            continue
        impacts.append(
            RevocationImpact(
                request_key=co.request_key,
                chain_id=event.chain_id,
                token_id=token_id,
                kind="co",
                side=side,
                redeemed_at=co.redeemed_at,
            )
        )

    impacts.sort(key=lambda i: (i.redeemed_at, i.request_key))
    return impacts


def insert_revocation_impacts(
    conn: sqlite3.Connection,
    event: RevocationEvent,
    impacts: list[RevocationImpact],
) -> None:
    """把影响清单随撤销事件一并落库（同一事务；只追加、不可变）。

    唯一约束 ``(revocation_request_key, access_request_key, chain_id, token_id)``
    兜底：同一事件的影响清单不会重复写入。
    """
    if not impacts:
        return
    created_at = event.created_at.astimezone(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO revocation_impacts (revocation_request_key, "
        "access_request_key, chain_id, token_id, kind, side, redeemed_at, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                event.request_key,
                i.request_key,
                i.chain_id,
                i.token_id,
                i.kind,
                i.side,
                i.redeemed_at.astimezone(timezone.utc).isoformat(),
                created_at,
            )
            for i in impacts
        ],
    )


def load_revocation_impacts(
    conn: sqlite3.Connection, request_key: str
) -> list[RevocationImpact]:
    """按撤销 request_key 查询已保存的影响清单，按 (核销时间, 访问键) 升序。"""
    rows = conn.execute(
        "SELECT access_request_key, chain_id, token_id, kind, side, redeemed_at "
        "FROM revocation_impacts WHERE revocation_request_key = ?",
        (request_key,),
    ).fetchall()
    impacts = [
        RevocationImpact(
            request_key=r["access_request_key"],
            chain_id=r["chain_id"],
            token_id=r["token_id"],
            kind=r["kind"],
            side=r["side"],
            redeemed_at=datetime.fromisoformat(r["redeemed_at"]),
        )
        for r in rows
    ]
    impacts.sort(key=lambda i: (i.redeemed_at, i.request_key))
    return impacts


# --------------------------------------------------------------------------- #
# 链末端 subject 的跨链成功核销总额度（未设置 = 不限额；已用量按成功记录实时统计）
# --------------------------------------------------------------------------- #
# 已用量口径（重启后不变，因为只依赖只追加的核销记录）：
#   1) redemptions 中被核销末端令牌的 subject = 该主体的成功单链核销，每笔计一次；
#   2) co_redemptions 中该主体作为主授权侧或复核侧参与的成功会签，
#      一笔会签对每个参与主体只计一次（两侧同主体的会签本就被接口禁止）。
# 追溯撤销 / 密钥停用不改写、不删除任何核销记录，故历史用量不退还；
# 成功请求的同键重放命中唯一约束回放原结果、不会再插入记录，故不重复计数。
_SINGLE_USAGE_SQL = """
SELECT COUNT(DISTINCT r.id) AS n
FROM redemptions AS r
WHERE EXISTS (
    SELECT 1 FROM tokens AS t
    WHERE t.chain_id = r.chain_id
      AND json_extract(t.token_json, '$.token_id') = r.token_id
      AND json_extract(t.token_json, '$.subject') = ?
)
"""

_CO_USAGE_SQL = """
SELECT COUNT(DISTINCT c.id) AS n
FROM co_redemptions AS c
WHERE (
    SELECT json_extract(t.token_json, '$.subject')
    FROM tokens AS t
    WHERE t.chain_id = c.primary_chain_id
      AND json_extract(t.token_json, '$.token_id') = c.primary_token_id
    LIMIT 1
) = ?
OR (
    SELECT json_extract(t.token_json, '$.subject')
    FROM tokens AS t
    WHERE t.chain_id = c.review_chain_id
      AND json_extract(t.token_json, '$.token_id') = c.review_token_id
    LIMIT 1
) = ?
"""


def count_subject_redemption_usage(conn: sqlite3.Connection, subject: str) -> int:
    """统计某链末端 subject 的累计成功核销次数（单链 + 会签参与侧）。

    统计基于成功核销记录表与随链持久化的令牌 subject，在调用方持有的事务内
    读取：核销 / 会签 / 额度调整均以 ``BEGIN IMMEDIATE`` 串行化，故并发核销
    与额度调整看到的是同一份已提交用量，不会超发。
    """
    single_n = conn.execute(_SINGLE_USAGE_SQL, (subject,)).fetchone()["n"]
    co_n = conn.execute(_CO_USAGE_SQL, (subject, subject)).fetchone()["n"]
    return int(single_n) + int(co_n)


def load_quota_row(
    conn: sqlite3.Connection, subject: str
) -> tuple[int | None, datetime | None] | None:
    """主体的额度行 ``(limit, updated_at)``；从未设置返回 None。

    ``limit`` 为 None 表示额度已被显式清除（不限额）；无行与清除后的口径
    都是“不限额”，区别仅在是否保留了设置历史（``updated_at``）。
    """
    row = conn.execute(
        "SELECT limit_value, updated_at FROM redemption_quotas WHERE subject = ?",
        (subject,),
    ).fetchone()
    if row is None:
        return None
    return row["limit_value"], datetime.fromisoformat(row["updated_at"])


def get_quota_status(
    conn: sqlite3.Connection, subject: str, at: datetime | None = None
) -> QuotaStatus:
    """组装主体的额度口径（额度 / 已用量 / 有效预留 / 可用量）。

    ``reserved`` 只统计 ``expires_at`` 晚于 ``at``（缺省为当前时刻）的预留——
    过期预留自动释放，不再占份额；``available = limit - used - reserved``
    （未设置额度时 ``limit`` / ``remaining`` / ``available`` 均为 None）。
    """
    row = load_quota_row(conn, subject)
    limit = row[0] if row is not None else None
    updated_at = row[1] if row is not None else None
    used = count_subject_redemption_usage(conn, subject)
    reserved = count_active_reservations(conn, subject, at)
    remaining = None if limit is None else limit - used
    available = None if limit is None else limit - used - reserved
    return QuotaStatus(
        subject=subject,
        limit=limit,
        used=used,
        reserved=reserved,
        remaining=remaining,
        available=available,
        updated_at=updated_at,
    )


def upsert_quota(
    conn: sqlite3.Connection,
    subject: str,
    limit: int | None,
    updated_at: datetime,
) -> int | None:
    """设置 / 调整 / 清除主体额度（UPSERT），返回调整前的额度（未设置为 None）。

    调用方须先在同一 ``BEGIN IMMEDIATE`` 事务内以 :func:`get_quota_status`
    校验新额度不低于当前已用量；本函数只负责落库。
    """
    previous_row = load_quota_row(conn, subject)
    previous_limit = previous_row[0] if previous_row is not None else None
    conn.execute(
        "INSERT INTO redemption_quotas (subject, limit_value, updated_at) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(subject) DO UPDATE SET "
        "limit_value = excluded.limit_value, updated_at = excluded.updated_at",
        (subject, limit, updated_at.astimezone(timezone.utc).isoformat()),
    )
    return previous_limit


# --------------------------------------------------------------------------- #
# 短时额度预留（成功预留才落库；过期自动释放，核销成功后转为已用删除）
# --------------------------------------------------------------------------- #
_RESERVATION_COLUMNS = (
    "chain_id, token_id, reservation_key, subject, request_path, method, "
    "source_ip, request_body, content_sha256, created_at, expires_at"
)


def load_reservation_by_key(
    conn: sqlite3.Connection, reservation_key: str
) -> tuple[ReservationEvent, str] | None:
    """返回（预留事件, 首次响应 JSON）；未见过该 reservation_key 时返回 None。

    调用方须自行按 ``expires_at`` 判定预留是否仍有效：过期预留视为已释放
    （键与令牌都不再被占用），由写事务内的调用方惰性清除。
    """
    row = conn.execute(
        f"SELECT {_RESERVATION_COLUMNS}, result_json FROM reservations "
        "WHERE reservation_key = ?",
        (reservation_key,),
    ).fetchone()
    if row is None:
        return None
    return _reservation_from_row(row), row["result_json"]


def load_reservation_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> ReservationEvent | None:
    """该令牌当前的预留记录（同一令牌至多一行，即至多一笔有效预留）。

    不过滤过期：是否仍有效由调用方按 ``expires_at`` 判定（过期即视为释放）。
    """
    row = conn.execute(
        f"SELECT {_RESERVATION_COLUMNS} FROM reservations "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _reservation_from_row(row) if row else None


def insert_reservation(
    conn: sqlite3.Connection, event: ReservationEvent, result_json: str
) -> None:
    """追加一条预留记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO reservations (chain_id, token_id, reservation_key, subject, "
        "request_path, method, source_ip, request_body, content_sha256, "
        "created_at, expires_at, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.reservation_key,
            event.subject,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.created_at.astimezone(timezone.utc).isoformat(),
            event.expires_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def delete_reservation(conn: sqlite3.Connection, reservation_key: str) -> None:
    """删除一条预留（过期惰性释放，或核销成功后把份额转为已用）。"""
    conn.execute(
        "DELETE FROM reservations WHERE reservation_key = ?", (reservation_key,)
    )


def count_active_reservations(
    conn: sqlite3.Connection, subject: str, at: datetime | None = None
) -> int:
    """某主体当前的有效预留数（``expires_at`` 晚于 ``at``；过期自动释放）。"""
    moment = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM reservations "
        "WHERE subject = ? AND expires_at > ?",
        (subject, moment.isoformat()),
    ).fetchone()
    return int(row["n"])


def _reservation_from_row(row: sqlite3.Row) -> ReservationEvent:
    return ReservationEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        reservation_key=row["reservation_key"],
        subject=row["subject"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]),
    )
