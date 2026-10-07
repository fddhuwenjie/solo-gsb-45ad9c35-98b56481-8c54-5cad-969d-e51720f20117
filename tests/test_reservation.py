"""短时额度预留：预留 / 重放 / 冲突 / 过期释放、额度口径三分（已用 / 预留 / 可用）、
普通核销与会签不得占用预留份额或令牌、调低额度不得侵占预留、核销携带预留键
匹配核销并转为已用、不匹配 / 过期 / 授权拒绝不占键不计已用、同键重试回放首次结果。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.database import get_conn
from app.main import app
from tests.conftest import make_token

_chain_seq = itertools.count(1)
_subj_seq = itertools.count(1)


def _subj(base: str) -> str:
    """唯一名：会话级共享数据库下隔离各用例的主体（避免跨文件历史用量串入）。"""
    return f"{base}-{next(_subj_seq)}"


def _now_window(**offsets) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=offsets.get("nb", -3600))
    na = now + timedelta(seconds=offsets.get("na", 3600))
    return (
        nb.isoformat().replace("+00:00", "Z"),
        na.isoformat().replace("+00:00", "Z"),
    )


def _two_token_chain(
    chain_id: str,
    leaf_id: str,
    leaf_subject: str,
    leaf_issuer: str = "svc-a",
    *,
    path: str = "/files/reports/x",
    allow_ip: str | None = None,
) -> dict:
    """root -> leaf 的合法两级链（对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        f"{leaf_id}-root", None, "root", leaf_issuer,
        "/files/**", ["GET", "POST"], not_before=nb, not_after=na,
        chain_id=chain_id,
    )
    leaf = make_token(
        leaf_id, f"{leaf_id}-root", leaf_issuer, leaf_subject,
        path, ["GET"], allow_ip=allow_ip,
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def _chain_with_tip_subject(client, subject: str) -> tuple[str, str]:
    """提交一条末端 subject 为 subject 的链，返回 (chain_id, leaf_token_id)。"""
    n = next(_chain_seq)
    chain_id, leaf_id = f"rsv-chain-{n}", f"rsv-leaf-{n}"
    resp = client.post(
        "/api/v1/chains",
        json=_two_token_chain(chain_id, leaf_id, subject),
    )
    assert resp.status_code == 201, resp.text
    return chain_id, leaf_id


def _set_quota(client, subject: str, limit):
    return client.put(
        f"/api/v1/subjects/{subject}/redemption-quota",
        json={"limit": limit},
    )


def _get_quota(client, subject: str):
    return client.get(f"/api/v1/subjects/{subject}/redemption-quota")


def _reserve(client, chain_id, token_id, reservation_key, *, ttl=60,
             path="/files/reports/x", method="GET", source_ip=None, body=None):
    payload = {
        "token_id": token_id,
        "reservation_key": reservation_key,
        "ttl_seconds": ttl,
        "request_path": path,
        "method": method,
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    return client.post(f"/api/v1/chains/{chain_id}/reservations", json=payload)


def _redeem(client, chain_id, token_id, request_key, *, path="/files/reports/x",
            method="GET", source_ip=None, body=None, reservation_key=None):
    payload = {
        "token_id": token_id,
        "request_key": request_key,
        "request_path": path,
        "method": method,
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    if reservation_key is not None:
        payload["reservation_key"] = reservation_key
    return client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)


def _co_redeem(client, primary, review, request_key, *,
               path="/files/reports/x", source_ip=None):
    payload = {
        "primary": {"chain_id": primary[0], "token_id": primary[1]},
        "review": {"chain_id": review[0], "token_id": review[1]},
        "request_key": request_key,
        "request_path": path,
        "method": "GET",
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    return client.post("/api/v1/co-redemptions", json=payload)


def _expire_reservation(reservation_key: str) -> None:
    """把指定预留的到期时间改到过去（模拟自然过期，避免测试等待）。"""
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "UPDATE reservations SET expires_at = ? WHERE reservation_key = ?",
            (past, reservation_key),
        )


def _reservation_exists(reservation_key: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM reservations WHERE reservation_key = ?",
            (reservation_key,),
        ).fetchone()
        return row is not None


# --------------------------------------------------------------------------- #
# 预留：成功 / 重放 / 冲突 / 校验
# --------------------------------------------------------------------------- #
def test_reserve_success_returns_expires_and_quota(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)

    resp = _reserve(client, cid, leaf, "rsv-key-1", ttl=120)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["reserved"] is True
    assert data["replayed"] is False
    assert data["decision"] == "allow"
    assert data["deny_reason"] is None
    # 返回到期时间：接收时刻 + 有效秒数
    evaluated = datetime.fromisoformat(data["evaluated_at"])
    expires = datetime.fromisoformat(data["expires_at"])
    assert expires == evaluated + timedelta(seconds=120)
    # 占用一份后的口径：used=0、reserved=1、available=1
    assert data["quota"]["limit"] == 2
    assert data["quota"]["used"] == 0
    assert data["quota"]["reserved"] == 1
    assert data["quota"]["remaining"] == 2
    assert data["quota"]["available"] == 1

    got = _get_quota(client, s).json()
    assert got["reserved"] == 1 and got["available"] == 1
    assert got["used"] == 0 and got["remaining"] == 2


def test_reserve_replay_same_key_same_content_returns_first_result(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)

    first = _reserve(client, cid, leaf, "rsv-replay-1", ttl=90)
    assert first.status_code == 201

    replay = _reserve(client, cid, leaf, "rsv-replay-1", ttl=90)
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["reserved"] is True
    # 到期时间与首次完全一致，不顺延、不重复占份
    assert body["expires_at"] == first.json()["expires_at"]
    assert body["evaluated_at"] == first.json()["evaluated_at"]
    assert _get_quota(client, s).json()["reserved"] == 1


def test_reserve_same_key_different_content_conflicts(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-conflict-1", ttl=60).status_code == 201

    # 换路径 / 换 ttl / 换方法都属于换内容
    for kwargs in ({"path": "/files/reports/y"}, {"ttl": 61}, {"method": "POST"}):
        resp = _reserve(client, cid, leaf, "rsv-conflict-1", **kwargs)
        assert resp.status_code == 409, (kwargs, resp.text)
        detail = resp.json()["detail"]
        assert detail["reservation_key"] == "rsv-conflict-1"
        assert detail["existing_sha256"] != detail["received_sha256"]
    # 冲突不占份额
    assert _get_quota(client, s).json()["reserved"] == 1


def test_reserve_ttl_validation(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-ttl-0", ttl=0).status_code == 422
    assert _reserve(client, cid, leaf, "rsv-ttl-301", ttl=301).status_code == 422
    # 边界值 1 与 300 均合法
    assert _reserve(client, cid, leaf, "rsv-ttl-1", ttl=1).status_code == 201
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c2, l2, "rsv-ttl-300", ttl=300).status_code == 201


def test_reserve_requires_chain_and_token_and_tip(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)

    # 链不存在 -> 404
    assert _reserve(client, "no-such-chain", leaf, "rsv-404-a").status_code == 404
    # 令牌不属于链 -> 404
    assert _reserve(client, cid, "no-such-token", "rsv-404-b").status_code == 404
    # 目标非末端 -> 409（根令牌不是末端）
    resp = _reserve(client, cid, f"{leaf}-root", "rsv-409-tip")
    assert resp.status_code == 409
    assert resp.json()["detail"]["chain_tip_token_id"] == leaf
    # 失败不占键：换合法目标后同键可用
    assert _reserve(client, cid, leaf, "rsv-409-tip").status_code == 201


def test_reserve_denied_by_authorization_keeps_key_and_quota(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)

    # 方法不被授权 -> 判定拒绝：不预留、不占键
    resp = _reserve(client, cid, leaf, "rsv-deny-1", method="POST")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reserved"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "method_not_allowed"
    assert data["deny_reason"] is None
    assert data["quota"] is None
    assert data["expires_at"] is None
    assert _get_quota(client, s).json()["reserved"] == 0

    # 同键修正内容后可成功（失败未占键）
    ok = _reserve(client, cid, leaf, "rsv-deny-1", method="GET")
    assert ok.status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 1


def test_reserve_requires_quota_set(client):
    s = _subj("rsv")  # 不设额度
    cid, leaf = _chain_with_tip_subject(client, s)
    resp = _reserve(client, cid, leaf, "rsv-unset-1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reserved"] is False
    assert data["decision"] == "allow"
    assert data["deny_reason"] == "quota_unset"
    assert data["quota"]["limit"] is None
    assert data["quota"]["available"] is None
    # 不占键：设置额度后同键成功
    assert _set_quota(client, s, 1).status_code == 200
    assert _reserve(client, cid, leaf, "rsv-unset-1").status_code == 201


def test_reserve_quota_exhausted_by_used_or_reserved(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)

    # 第一笔预留占满可用量
    assert _reserve(client, c1, l1, "rsv-full-1").status_code == 201
    # 第二笔：available = 1 - 0 - 1 = 0 -> 拒绝，不占键
    resp = _reserve(client, c2, l2, "rsv-full-2")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reserved"] is False
    assert data["decision"] == "allow"
    assert data["deny_reason"] == "quota_exhausted"
    assert data["quota"]["reserved"] == 1
    assert data["quota"]["available"] == 0
    assert _get_quota(client, s).json()["reserved"] == 1

    # 调高额度后同键成功（之前未占键）
    assert _set_quota(client, s, 2).status_code == 200
    assert _reserve(client, c2, l2, "rsv-full-2").status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 2


def test_one_active_reservation_per_token(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 3).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-one-1").status_code == 201

    # 同一令牌换键再预留 -> 409，响应给出已有预留的键与到期时间
    resp = _reserve(client, cid, leaf, "rsv-one-2")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["existing_reservation_key"] == "rsv-one-1"
    assert "expires_at" in detail
    # 第二把键未被占用：过期释放后仍可用于其他令牌
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c2, l2, "rsv-one-2").status_code == 201


def test_reserve_rejects_already_redeemed_token(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _redeem(client, cid, leaf, "rsv-redeemed-rk").status_code == 201

    resp = _reserve(client, cid, leaf, "rsv-after-redeem")
    assert resp.status_code == 409
    assert resp.json()["detail"]["existing_request_key"] == "rsv-redeemed-rk"


# --------------------------------------------------------------------------- #
# 过期自动释放
# --------------------------------------------------------------------------- #
def test_expired_reservation_releases_quota_token_and_key(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c1, l1, "rsv-exp-1", ttl=1).status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 1

    _expire_reservation("rsv-exp-1")

    # 过期自动释放：不再占额度
    got = _get_quota(client, s).json()
    assert got["reserved"] == 0 and got["available"] == 1
    # 同一令牌可重新预留（不再被旧预留占用）
    assert _reserve(client, c1, l1, "rsv-exp-2").status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 1


def test_expired_reservation_same_key_retried_as_new(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    first = _reserve(client, cid, leaf, "rsv-exp-key", ttl=1)
    assert first.status_code == 201

    _expire_reservation("rsv-exp-key")

    # 过期后同键同内容重试：按一笔全新预留处理（新的到期时间）
    again = _reserve(client, cid, leaf, "rsv-exp-key", ttl=1)
    assert again.status_code == 201
    assert again.json()["replayed"] is False
    assert again.json()["expires_at"] != first.json()["expires_at"]
    assert _get_quota(client, s).json()["reserved"] == 1


# --------------------------------------------------------------------------- #
# 额度查询三分：历史已用 / 有效预留 / 可用量
# --------------------------------------------------------------------------- #
def test_quota_status_distinguishes_used_reserved_available(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 3).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    c3, l3 = _chain_with_tip_subject(client, s)

    # 1 次成功核销（历史已用）+ 1 笔有效预留
    assert _redeem(client, c1, l1, "rsv-mix-redeem").status_code == 201
    assert _reserve(client, c2, l2, "rsv-mix-reserve").status_code == 201

    got = _get_quota(client, s).json()
    assert got["limit"] == 3
    assert got["used"] == 1
    assert got["reserved"] == 1
    assert got["remaining"] == 2  # limit - used（含预留份额）
    assert got["available"] == 1  # limit - used - reserved

    # 可用量只剩 1：第三笔预留成功，第四笔（另一令牌）被拒绝
    assert _reserve(client, c3, l3, "rsv-mix-reserve-2").status_code == 201
    c4, l4 = _chain_with_tip_subject(client, s)
    denied = _reserve(client, c4, l4, "rsv-mix-reserve-3")
    assert denied.status_code == 200
    assert denied.json()["deny_reason"] == "quota_exhausted"


# --------------------------------------------------------------------------- #
# 普通核销 / 会签不得占用预留额度或令牌
# --------------------------------------------------------------------------- #
def test_plain_redeem_cannot_use_reserved_token(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-hold-1").status_code == 201

    # 不带预留键的普通核销：不得占用被预留的令牌
    resp = _redeem(client, cid, leaf, "rsv-hold-rk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["deny_reason"] == "token_reserved"
    # 不占核销键、不计已用
    assert _get_quota(client, s).json()["used"] == 0
    assert client.get(f"/api/v1/chains/{cid}").json()["redemptions"] == []

    # 预留过期后，同一把 request_key 的普通核销成功（之前未占键）
    _expire_reservation("rsv-hold-1")
    ok = _redeem(client, cid, leaf, "rsv-hold-rk")
    assert ok.status_code == 201
    assert _get_quota(client, s).json()["used"] == 1


def test_plain_redeem_cannot_spend_reserved_quota_share(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)

    # 预留占满唯一一份额度（另一令牌的预留）
    assert _reserve(client, c1, l1, "rsv-share-1").status_code == 201
    # 普通核销另一条链的末端：可用量为 0 -> quota_exhausted，不占键
    resp = _redeem(client, c2, l2, "rsv-share-rk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["deny_reason"] == "quota_exhausted"
    assert data["quota"]["reserved"] == 1
    assert data["quota"]["available"] == 0

    # 预留过期释放后，同一把键成功
    _expire_reservation("rsv-share-1")
    assert _redeem(client, c2, l2, "rsv-share-rk").status_code == 201


def test_co_redeem_cannot_use_reserved_token_or_quota(client):
    s1, s2 = _subj("rsv-co-a"), _subj("rsv-co-b")
    assert _set_quota(client, s1, 1).status_code == 200
    p1 = _chain_with_tip_subject(client, s1)
    r1 = _chain_with_tip_subject(client, s2)

    # 主授权侧令牌被预留 -> 会签不得占用（两侧都不核销、不占键）
    assert _reserve(client, p1[0], p1[1], "rsv-co-hold").status_code == 201
    resp = _co_redeem(client, p1, r1, "rsv-co-rk-1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["primary"]["deny_reason"] == "token_reserved"
    assert data["review"]["decision"] == "allow"
    assert _get_quota(client, s1).json()["used"] == 0
    assert _get_quota(client, s2).json()["used"] == 0

    # 预留过期后同键会签成功
    _expire_reservation("rsv-co-hold")
    ok = _co_redeem(client, p1, r1, "rsv-co-rk-1")
    assert ok.status_code == 201, ok.text

    # 主授权侧额度 1 已被会签用掉；再预留一笔（另一令牌）后，
    # 新会签因可用量不足被拒绝（reserved 占的是别人预留的份额）
    p2 = _chain_with_tip_subject(client, s1)
    r2 = _chain_with_tip_subject(client, s2)
    p3 = _chain_with_tip_subject(client, s1)
    r3 = _chain_with_tip_subject(client, s2)
    assert _set_quota(client, s1, 2).status_code == 200
    assert _reserve(client, p2[0], p2[1], "rsv-co-hold-2").status_code == 201
    resp2 = _co_redeem(client, p3, r3, "rsv-co-rk-2")
    assert resp2.status_code == 200
    assert resp2.json()["primary"]["deny_reason"] == "quota_exhausted"
    assert resp2.json()["primary"]["quota"]["reserved"] == 1


def test_lower_quota_cannot_encroach_reserved(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-encroach").status_code == 201

    # used=0、reserved=1：调低到 0 侵占预留 -> 409
    resp = _set_quota(client, s, 0)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["reserved"] == 1
    assert detail["used"] == 0
    # 调低到 1（= used + reserved）允许
    assert _set_quota(client, s, 1).status_code == 200
    # 预留过期释放后，调低到 0 不再侵占
    _expire_reservation("rsv-encroach")
    assert _set_quota(client, s, 0).status_code == 200


# --------------------------------------------------------------------------- #
# 核销携带预留键：匹配核销、转为已用；不匹配 / 过期 / 授权拒绝不占键不计已用
# --------------------------------------------------------------------------- #
def test_redeem_with_matching_reservation_converts_to_used(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-use-1", body={"q": 1}).status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 1

    # 携带预留键、同访问内容：核销成功，同一事务内预留转为已用
    resp = _redeem(client, cid, leaf, "rsv-use-rk", reservation_key="rsv-use-1",
                   body={"q": 1})
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["redeemed"] is True
    assert data["quota"]["used"] == 1
    assert data["quota"]["reserved"] == 0
    assert data["quota"]["available"] == 0

    got = _get_quota(client, s).json()
    assert got["used"] == 1 and got["reserved"] == 0
    # 预留行已删除（转为已用）
    assert _reservation_exists("rsv-use-1") is False

    # 成功核销同键重试：返回首次结果（replayed=true，口径与首次一致）
    replay = _redeem(client, cid, leaf, "rsv-use-rk", reservation_key="rsv-use-1",
                     body={"q": 1})
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed"] is True
    assert replay.json()["quota"]["used"] == 1
    assert _get_quota(client, s).json()["used"] == 1


def test_redeem_with_reservation_allows_redeem_even_when_available_zero(client):
    # 预留份额就是给这次核销的：即使 available=0，带匹配预留键的核销仍成功
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-use-full").status_code == 201
    assert _get_quota(client, s).json()["available"] == 0

    resp = _redeem(client, cid, leaf, "rsv-use-full-rk",
                   reservation_key="rsv-use-full")
    assert resp.status_code == 201
    assert _get_quota(client, s).json()["used"] == 1


def test_redeem_with_unknown_or_mismatched_reservation_key(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-mm-1").status_code == 201

    # 预留键不存在
    resp = _redeem(client, cid, leaf, "rsv-mm-rk-1", reservation_key="no-such-key")
    assert resp.status_code == 200
    assert resp.json()["redeemed"] is False
    assert resp.json()["deny_reason"] == "reservation_mismatch"

    # 键存在但访问内容不符（路径不同）
    resp2 = _redeem(client, cid, leaf, "rsv-mm-rk-2", reservation_key="rsv-mm-1",
                    path="/files/reports/other")
    assert resp2.status_code == 200
    assert resp2.json()["deny_reason"] == "reservation_mismatch"

    # 键存在但来源 IP 不符（预留无 IP 限制，核销带了 IP 也算内容不符）
    resp3 = _redeem(client, cid, leaf, "rsv-mm-rk-3", reservation_key="rsv-mm-1",
                    source_ip="10.0.0.1")
    assert resp3.status_code == 200
    assert resp3.json()["deny_reason"] == "reservation_mismatch"

    # 均不占核销键、不计已用；预留仍有效
    got = _get_quota(client, s).json()
    assert got["used"] == 0 and got["reserved"] == 1
    assert client.get(f"/api/v1/chains/{cid}").json()["redemptions"] == []

    # 同一把 request_key 修正内容后成功（之前未占键）
    ok = _redeem(client, cid, leaf, "rsv-mm-rk-1", reservation_key="rsv-mm-1")
    assert ok.status_code == 201


def test_redeem_with_expired_reservation_key_is_mismatch(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-expired-use", ttl=1).status_code == 201
    _expire_reservation("rsv-expired-use")

    # 预留已过期：携带该键的核销按不匹配拒绝，不占核销键、不计已用
    resp = _redeem(client, cid, leaf, "rsv-expired-rk",
                   reservation_key="rsv-expired-use")
    assert resp.status_code == 200
    assert resp.json()["redeemed"] is False
    assert resp.json()["deny_reason"] == "reservation_mismatch"
    assert _get_quota(client, s).json()["used"] == 0

    # 过期预留已释放：不带键的普通核销同键成功
    ok = _redeem(client, cid, leaf, "rsv-expired-rk")
    assert ok.status_code == 201


def test_redeem_with_reservation_rechecks_authorization(client):
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-recheck").status_code == 201

    # 预留后撤销末端令牌：携带匹配预留键的核销仍重新检查授权 -> 拒绝
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post(
        f"/api/v1/chains/{cid}/revocations",
        json={"token_id": leaf, "effective_at": now,
              "reason": "预留后撤销，核销须重新检查", "request_key": "rsv-revoke-op"},
    ).status_code == 201

    resp = _redeem(client, cid, leaf, "rsv-recheck-rk",
                   reservation_key="rsv-recheck")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "revoked"
    # 授权拒绝：不占核销键、不计已用；预留仍保留（未到期）
    got = _get_quota(client, s).json()
    assert got["used"] == 0 and got["reserved"] == 1
    assert client.get(f"/api/v1/chains/{cid}").json()["redemptions"] == []


def test_redeem_with_reservation_key_is_part_of_content_hash(client):
    # 同一 request_key：首次带预留键核销成功后，不带键重试属于换内容 -> 409
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-hash").status_code == 201
    assert _redeem(client, cid, leaf, "rsv-hash-rk",
                   reservation_key="rsv-hash").status_code == 201

    resp = _redeem(client, cid, leaf, "rsv-hash-rk")
    assert resp.status_code == 409


def test_old_redeem_without_reservation_still_works(client):
    # 旧调用（不带预留键）在没有任何预留时照常核销
    s = _subj("rsv")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    resp = _redeem(client, cid, leaf, "rsv-legacy-rk")
    assert resp.status_code == 201
    assert resp.json()["quota"]["used"] == 1
    assert resp.json()["quota"]["reserved"] == 0


# --------------------------------------------------------------------------- #
# 并发：预留不超发；预留与核销并发不超发
# --------------------------------------------------------------------------- #
def test_concurrent_reservations_never_exceed_available(client):
    s = _subj("rsv-conc")
    assert _set_quota(client, s, 2).status_code == 200
    targets = [_chain_with_tip_subject(client, s) for _ in range(8)]
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        cid, leaf = targets[i]
        resp = _reserve(client, cid, leaf, f"rsv-conc-{i}")
        results.append((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0] == 201]
    exhausted = [
        r for r in results
        if r[0] == 200 and r[1].get("deny_reason") == "quota_exhausted"
    ]
    assert len(created) == 2
    assert len(exhausted) == 6
    got = _get_quota(client, s).json()
    assert got["reserved"] == 2 and got["available"] == 0


def test_concurrent_reserve_and_redeem_never_overshoot(client):
    # 额度 1：一笔预留与一笔普通核销并发，合计占用不得超过 1
    s = _subj("rsv-mix-conc")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    outcomes: list[tuple[str, int]] = []
    barrier = threading.Barrier(2)

    def reserve_worker() -> None:
        barrier.wait()
        resp = _reserve(client, c1, l1, "rsv-mix-conc-reserve")
        outcomes.append(("reserve", resp.status_code))

    def redeem_worker() -> None:
        barrier.wait()
        resp = _redeem(client, c2, l2, "rsv-mix-conc-redeem")
        outcomes.append(("redeem", resp.status_code))

    threads = [threading.Thread(target=reserve_worker),
               threading.Thread(target=redeem_worker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    got = _get_quota(client, s).json()
    assert got["used"] + got["reserved"] <= 1
    assert got["available"] == 1 - got["used"] - got["reserved"]
