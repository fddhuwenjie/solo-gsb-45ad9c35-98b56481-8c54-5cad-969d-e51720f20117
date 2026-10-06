"""单链访问的短时额度预留：创建 / 重放 / 冲突 / 过期自动释放、与核销 / 会签 /
额度调整的隔离（普通核销与会签不能占用预留额度或令牌、调低额度不侵占预留）、
携带预留键核销（匹配 / 不匹配 / 过期 / 授权重检）、同事务转已用、并发不超发。"""
from __future__ import annotations

import itertools
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

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
    path: str = "/files/reports/*",
    allow_ip: str | None = None,
    leaf_secret: str | None = None,
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
        secret=leaf_secret,
    )
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def _chain_with_tip_subject(
    client, subject: str, *, path: str = "/files/reports/*", allow_ip=None
) -> tuple[str, str]:
    """提交一条末端 subject 为 subject 的链，返回 (chain_id, leaf_token_id)。"""
    n = next(_chain_seq)
    chain_id, leaf_id = f"rsv-chain-{n}", f"rsv-leaf-{n}"
    resp = client.post(
        "/api/v1/chains",
        json=_two_token_chain(chain_id, leaf_id, subject, path=path,
                              allow_ip=allow_ip),
    )
    assert resp.status_code == 201, resp.text
    return chain_id, leaf_id


def _set_quota(client, subject: str, limit):
    return client.put(
        f"/api/v1/subjects/{subject}/redemption-quota", json={"limit": limit}
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


def _redeem(client, chain_id, token_id, request_key, *, reservation_key=None,
            path="/files/reports/x", method="GET", source_ip=None, body=None):
    payload = {
        "token_id": token_id,
        "request_key": request_key,
        "request_path": path,
        "method": method,
    }
    if reservation_key is not None:
        payload["reservation_key"] = reservation_key
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    return client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)


def _co_redeem(client, primary, review, request_key, *, path="/files/reports/x"):
    payload = {
        "primary": {"chain_id": primary[0], "token_id": primary[1]},
        "review": {"chain_id": review[0], "token_id": review[1]},
        "request_key": request_key,
        "request_path": path,
        "method": "GET",
    }
    return client.post("/api/v1/co-redemptions", json=payload)


# --------------------------------------------------------------------------- #
# 创建预留：成功、额度口径、前提条件
# --------------------------------------------------------------------------- #
def test_reserve_success_holds_one_share_and_returns_expiry(client):
    s = _subj("alice")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)

    resp = _reserve(client, cid, leaf, "rsv-ok-1", ttl=120)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["reserved"] is True
    assert data["replayed"] is False
    assert data["decision"] == "allow"
    assert data["chain_id"] == cid
    assert data["token_id"] == leaf
    assert data["reservation_key"] == "rsv-ok-1"
    # 到期时间 = 接收时刻 + 有效秒数
    evaluated = datetime.fromisoformat(data["evaluated_at"])
    expires = datetime.fromisoformat(data["expires_at"])
    assert expires - evaluated == timedelta(seconds=120)
    # 占一份额度：reserved=1，available 减 1，历史已用不变
    assert data["quota"] == {
        "subject": s,
        "limit": 2,
        "used": 0,
        "remaining": 2,
        "reserved": 1,
        "available": 1,
        "updated_at": data["quota"]["updated_at"],
    }
    # 额度查询同样区分历史已用 / 有效预留 / 可用量
    got = _get_quota(client, s).json()
    assert got["used"] == 0
    assert got["reserved"] == 1
    assert got["available"] == 1
    assert got["remaining"] == 2


def test_reserve_requires_quota_to_be_set(client):
    s = _subj("nolimit")
    cid, leaf = _chain_with_tip_subject(client, s)
    resp = _reserve(client, cid, leaf, "rsv-nolimit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reserved"] is False
    assert data["decision"] == "allow"
    assert data["deny_reason"] == "quota_not_set"
    assert data["quota"] is None
    # 失败不占键：设置额度后同一把键即可成功
    assert _set_quota(client, s, 1).status_code == 200
    ok = _reserve(client, cid, leaf, "rsv-nolimit")
    assert ok.status_code == 201
    assert ok.json()["reserved"] is True


def test_reserve_denied_when_available_exhausted_by_other_reservation(client):
    s = _subj("full")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c1, l1, "rsv-full-1").status_code == 201
    # 可用量 0（1 份被预留）：第二笔预留明确拒绝，不占键
    denied = _reserve(client, c2, l2, "rsv-full-2")
    assert denied.status_code == 200
    data = denied.json()
    assert data["reserved"] is False
    assert data["deny_reason"] == "quota_exhausted"
    assert data["quota"]["reserved"] == 1
    assert data["quota"]["available"] == 0
    # 调高额度后同一把键成功
    assert _set_quota(client, s, 2).status_code == 200
    ok = _reserve(client, c2, l2, "rsv-full-2")
    assert ok.status_code == 201


def test_reserve_denied_when_authorization_fails_and_key_not_occupied(client):
    s = _subj("deny")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    # 方法不被允许 -> 授权拒绝：不预留、不占键
    resp = _reserve(client, cid, leaf, "rsv-deny", method="POST")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reserved"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "method_not_allowed"
    assert data["deny_reason"] is None
    assert _get_quota(client, s).json()["reserved"] == 0
    # 同一把键修正方法后成功
    ok = _reserve(client, cid, leaf, "rsv-deny", method="GET")
    assert ok.status_code == 201


def test_reserve_replay_returns_original_and_conflict_on_different_content(client):
    s = _subj("replay")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    first = _reserve(client, cid, leaf, "rsv-replay", ttl=90)
    assert first.status_code == 201

    # 同键同内容重放：返回首次预留（同样的到期时间），不重复占份额
    replay = _reserve(client, cid, leaf, "rsv-replay", ttl=90)
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["reserved"] is True
    assert body["expires_at"] == first.json()["expires_at"]
    assert body["evaluated_at"] == first.json()["evaluated_at"]
    assert _get_quota(client, s).json()["reserved"] == 1

    # 同键换内容（不同 ttl / 路径 / 方法）-> 409
    for kwargs in ({"ttl": 60}, {"path": "/files/reports/y"}, {"method": "POST"}):
        conflict = _reserve(client, cid, leaf, "rsv-replay", **kwargs)
        assert conflict.status_code == 409, kwargs
        detail = conflict.json()["detail"]
        assert detail["existing_sha256"] != detail["received_sha256"]


def test_reserve_one_active_reservation_per_token(client):
    s = _subj("onetoken")
    assert _set_quota(client, s, 3).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-one-1", ttl=1).status_code == 201
    # 同一令牌已有有效预留：第二笔（换键）冲突
    conflict = _reserve(client, cid, leaf, "rsv-one-2")
    assert conflict.status_code == 409
    detail = conflict.json()["detail"]
    assert detail["existing_reservation_key"] == "rsv-one-1"
    assert "reservation_expires_at" in detail
    # 过期自动释放后，同一令牌可再预留
    time.sleep(1.2)
    ok = _reserve(client, cid, leaf, "rsv-one-2")
    assert ok.status_code == 201
    assert _get_quota(client, s).json()["reserved"] == 1


def test_reserve_rejects_redeemed_token_non_tip_and_missing(client):
    s = _subj("edges")
    assert _set_quota(client, s, 5).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    # 先核销：已核销令牌不能再预留
    assert _redeem(client, cid, leaf, "rsv-edge-redeem").status_code == 201
    redeemed = _reserve(client, cid, leaf, "rsv-edge-1")
    assert redeemed.status_code == 409
    assert redeemed.json()["detail"]["existing_request_key"] == "rsv-edge-redeem"

    # 非末端令牌 -> 409
    cid2, leaf2 = _chain_with_tip_subject(client, s)
    not_tip = _reserve(client, cid2, f"{leaf2}-root", "rsv-edge-2")
    assert not_tip.status_code == 409
    assert not_tip.json()["detail"]["chain_tip_token_id"] == leaf2

    # 链 / 令牌不存在 -> 404
    assert _reserve(client, "no-such-chain", "x", "rsv-edge-3").status_code == 404
    assert _reserve(client, cid2, "no-such-token", "rsv-edge-4").status_code == 404

    # ttl 越界 -> 422
    assert _reserve(client, cid2, leaf2, "rsv-edge-5", ttl=0).status_code == 422
    assert _reserve(client, cid2, leaf2, "rsv-edge-6", ttl=301).status_code == 422


def test_reserve_expired_reservation_releases_share_automatically(client):
    s = _subj("expire")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c1, l1, "rsv-exp-1", ttl=1).status_code == 201
    assert _get_quota(client, s).json()["available"] == 0
    # 过期自动释放：可用量恢复，另一令牌可预留
    time.sleep(1.2)
    got = _get_quota(client, s).json()
    assert got["reserved"] == 0
    assert got["available"] == 1
    assert _reserve(client, c2, l2, "rsv-exp-2").status_code == 201


# --------------------------------------------------------------------------- #
# 隔离：普通核销 / 会签不能占用预留额度或令牌；调低额度不侵占预留
# --------------------------------------------------------------------------- #
def test_plain_redeem_cannot_use_reserved_quota_share(client):
    s = _subj("shield")
    assert _set_quota(client, s, 1).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c1, l1, "rsv-shield-1").status_code == 201
    # 另一条链的普通核销：唯一一份额度被预留占用 -> quota_exhausted
    denied = _redeem(client, c2, l2, "rsv-shield-rk")
    assert denied.status_code == 200
    data = denied.json()
    assert data["redeemed"] is False
    assert data["deny_reason"] == "quota_exhausted"
    assert data["quota"]["reserved"] == 1
    assert data["quota"]["available"] == 0
    # 不占键、不计已用
    assert _get_quota(client, s).json()["used"] == 0


def test_plain_redeem_cannot_consume_reserved_token_until_expiry(client):
    s = _subj("lock")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-lock-1", ttl=1).status_code == 201
    # 未携带预留键的普通核销不能占用预留令牌 -> 409
    conflict = _redeem(client, cid, leaf, "rsv-lock-rk")
    assert conflict.status_code == 409
    detail = conflict.json()["detail"]
    assert detail["existing_reservation_key"] == "rsv-lock-1"
    # 预留过期自动释放后，普通核销照常可用
    time.sleep(1.2)
    ok = _redeem(client, cid, leaf, "rsv-lock-rk")
    assert ok.status_code == 201
    assert _get_quota(client, s).json()["used"] == 1


def test_co_redemption_cannot_consume_reserved_token_or_share(client):
    psub, rsub = _subj("cop"), _subj("cor")
    assert _set_quota(client, psub, 1).status_code == 200
    primary = _chain_with_tip_subject(client, psub)
    review = _chain_with_tip_subject(client, rsub)
    # 主授权侧令牌被预留：会签 409，两侧都不被消耗
    assert _reserve(client, primary[0], primary[1], "rsv-co-1").status_code == 201
    conflict = _co_redeem(client, primary, review, "rsv-co-rk")
    assert conflict.status_code == 409
    detail = conflict.json()["detail"]
    assert detail["side"] == "primary"
    assert detail["existing_reservation_key"] == "rsv-co-1"
    assert client.get(
        f"/api/v1/chains/{review[0]}"
    ).json()["redemptions"] == []
    assert _get_quota(client, rsub).json()["used"] == 0

    # 换一对链：主授权侧唯一一份额度被预留占用 -> 会签余额不足，两侧均不核销
    primary2 = _chain_with_tip_subject(client, psub)
    review2 = _chain_with_tip_subject(client, rsub)
    exhausted = _co_redeem(client, primary2, review2, "rsv-co-rk2")
    assert exhausted.status_code == 200
    data = exhausted.json()
    assert data["redeemed"] is False
    assert data["primary"]["deny_reason"] == "quota_exhausted"
    assert data["primary"]["quota"]["reserved"] == 1
    assert data["primary"]["quota"]["available"] == 0
    assert _get_quota(client, rsub).json()["used"] == 0


def test_lower_quota_cannot_encroach_on_active_reservation(client):
    s = _subj("lower")
    assert _set_quota(client, s, 3).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-lower-1").status_code == 201
    # used=0, reserved=1：调低到 0 侵占预留 -> 409，原额度不变
    resp = _set_quota(client, s, 0)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["used"] == 0
    assert detail["reserved"] == 1
    assert detail["requested_limit"] == 0
    assert _get_quota(client, s).json()["limit"] == 3
    # 调低到 used+reserved=1 可以；再低到 0 仍拒绝
    assert _set_quota(client, s, 1).status_code == 200
    assert _set_quota(client, s, 0).status_code == 409


# --------------------------------------------------------------------------- #
# 携带预留键核销：匹配 / 不匹配 / 过期 / 授权重检 / 同事务转已用 / 重放
# --------------------------------------------------------------------------- #
def test_redeem_with_matching_reservation_converts_share_in_same_transaction(client):
    s = _subj("use")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-use-1").status_code == 201
    # 可用量为 0，但持预留键核销使用预留份额 -> 成功
    resp = _redeem(client, cid, leaf, "rsv-use-rk", reservation_key="rsv-use-1")
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["redeemed"] is True
    # 同一事务把预留转为已用：used=1、reserved=0、available 不变（仍 0）
    assert data["quota"]["used"] == 1
    assert data["quota"]["reserved"] == 0
    assert data["quota"]["available"] == 0
    got = _get_quota(client, s).json()
    assert got["used"] == 1 and got["reserved"] == 0

    # 成功核销同键重试返回首次结果（含首次额度口径），不重复计数
    replay = _redeem(client, cid, leaf, "rsv-use-rk", reservation_key="rsv-use-1")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed_at"] == data["redeemed_at"]
    assert _get_quota(client, s).json()["used"] == 1

    # 预留已被消费：再用同一预留键核销另一令牌 -> 不匹配（且令牌未预留）
    c2, l2 = _chain_with_tip_subject(client, s)
    mismatch = _redeem(client, c2, l2, "rsv-use-rk2", reservation_key="rsv-use-1")
    assert mismatch.status_code == 200
    assert mismatch.json()["deny_reason"] == "reservation_mismatch"


def test_redeem_with_mismatched_reservation_content_denied_without_consuming(client):
    s = _subj("mismatch")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-mm-1", body={"a": 1}).status_code == 201

    # 路径不匹配（链模式允许两条路径，但访问内容与预留不同）
    bad_path = _redeem(client, cid, leaf, "rsv-mm-rk1",
                       reservation_key="rsv-mm-1", path="/files/reports/y",
                       body={"a": 1})
    assert bad_path.status_code == 200
    assert bad_path.json()["deny_reason"] == "reservation_mismatch"
    # 请求体不匹配
    bad_body = _redeem(client, cid, leaf, "rsv-mm-rk2",
                       reservation_key="rsv-mm-1", body={"a": 2})
    assert bad_body.json()["deny_reason"] == "reservation_mismatch"
    # 不存在的预留键
    no_key = _redeem(client, cid, leaf, "rsv-mm-rk3", reservation_key="rsv-mm-x")
    assert no_key.json()["deny_reason"] == "reservation_mismatch"
    # 都不占核销键、不计已用、预留不被消耗
    assert _get_quota(client, s).json()["used"] == 0
    assert _get_quota(client, s).json()["reserved"] == 1
    assert client.get(f"/api/v1/chains/{cid}").json()["redemptions"] == []
    # 同一把核销键携带匹配内容重试 -> 成功
    ok = _redeem(client, cid, leaf, "rsv-mm-rk1",
                 reservation_key="rsv-mm-1", body={"a": 1})
    assert ok.status_code == 201


def test_redeem_with_reservation_of_another_token_is_mismatch(client):
    s = _subj("othertoken")
    assert _set_quota(client, s, 2).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _reserve(client, c1, l1, "rsv-other-1").status_code == 201
    # 预留属于另一条链的令牌：用于本链核销 -> 不匹配
    resp = _redeem(client, c2, l2, "rsv-other-rk", reservation_key="rsv-other-1")
    assert resp.status_code == 200
    assert resp.json()["deny_reason"] == "reservation_mismatch"
    assert _get_quota(client, s).json()["used"] == 0


def test_redeem_with_expired_reservation_denied_then_plain_redeem_works(client):
    s = _subj("expired")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-expire-1", ttl=1).status_code == 201
    time.sleep(1.2)
    # 预留已过期：携带预留键核销 -> reservation_expired，不占核销键、不计已用
    resp = _redeem(client, cid, leaf, "rsv-expire-rk",
                   reservation_key="rsv-expire-1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["deny_reason"] == "reservation_expired"
    assert _get_quota(client, s).json()["used"] == 0
    # 过期预留已释放：同一把核销键改为普通核销即可成功
    ok = _redeem(client, cid, leaf, "rsv-expire-rk")
    assert ok.status_code == 201
    assert _get_quota(client, s).json()["used"] == 1


def test_redeem_with_reservation_rechecks_authorization_revocation_and_keys(client):
    s = _subj("recheck")
    issuer = s + "-issuer"
    assert client.post(
        "/api/v1/principals", json={"name": issuer, "hmac_secret": "recheck-secret"}
    ).status_code == 201
    assert _set_quota(client, s, 2).status_code == 200
    n = next(_chain_seq)
    chain_id, leaf_id = f"rsv-chain-{n}", f"rsv-leaf-{n}"
    chain = _two_token_chain(chain_id, leaf_id, s, leaf_issuer=issuer,
                             leaf_secret="recheck-secret")
    assert client.post("/api/v1/chains", json=chain).status_code == 201
    assert _reserve(client, chain_id, leaf_id, "rsv-recheck-1").status_code == 201

    # 预留后撤销末端令牌：核销时重新检查 -> 拒绝，预留不被消耗、不占核销键
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={"token_id": leaf_id, "effective_at": now,
              "reason": "预留后撤销", "request_key": "rsv-recheck-revoke"},
    ).status_code == 201
    denied = _redeem(client, chain_id, leaf_id, "rsv-recheck-rk1",
                     reservation_key="rsv-recheck-1")
    assert denied.status_code == 200
    data = denied.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "revoked"
    assert _get_quota(client, s).json()["used"] == 0
    assert _get_quota(client, s).json()["reserved"] == 1  # 预留未被消耗

    # 换一条链：预留后停用签发密钥 -> 核销时重新检查 -> key_deactivated 拒绝
    n = next(_chain_seq)
    chain2, leaf2 = f"rsv-chain-{n}", f"rsv-leaf-{n}"
    chain2_body = _two_token_chain(chain2, leaf2, s, leaf_issuer=issuer,
                                   leaf_secret="recheck-secret")
    assert client.post("/api/v1/chains", json=chain2_body).status_code == 201
    assert _reserve(client, chain2, leaf2, "rsv-recheck-2").status_code == 201
    assert client.post(
        f"/api/v1/principals/{issuer}/generations/1/deactivate-key",
        json={"reason": "疑似失陷"},
    ).status_code == 201
    denied2 = _redeem(client, chain2, leaf2, "rsv-recheck-rk2",
                      reservation_key="rsv-recheck-2")
    assert denied2.status_code == 200
    assert denied2.json()["first_failed_reason"] == "key_deactivated"
    assert _get_quota(client, s).json()["used"] == 0
    assert _get_quota(client, s).json()["reserved"] == 2


def test_reserve_replay_after_consumption_returns_original(client):
    s = _subj("consumed")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    first = _reserve(client, cid, leaf, "rsv-consumed-1", ttl=90)
    assert first.status_code == 201
    assert _redeem(client, cid, leaf, "rsv-consumed-rk",
                   reservation_key="rsv-consumed-1").status_code == 201
    # 预留已被消费：同键同内容重放仍返回首次预留结果
    replay = _reserve(client, cid, leaf, "rsv-consumed-1", ttl=90)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["expires_at"] == first.json()["expires_at"]


# --------------------------------------------------------------------------- #
# 并发与重启
# --------------------------------------------------------------------------- #
def test_concurrent_reservations_never_exceed_available(client):
    s = _subj("conc")
    assert _set_quota(client, s, 1).status_code == 200
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
    assert len(created) == 1
    assert len(exhausted) == 7
    got = _get_quota(client, s).json()
    assert got["reserved"] == 1 and got["available"] == 0


def test_reservation_and_quota_survive_restart(client):
    s = _subj("restart")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _reserve(client, cid, leaf, "rsv-restart-1", ttl=300).status_code == 201

    # 模拟重启：同一数据库文件上重新进入应用生命周期，口径不变
    with TestClient(app) as c2:
        got = c2.get(f"/api/v1/subjects/{s}/redemption-quota").json()
        assert got["limit"] == 2
        assert got["used"] == 0
        assert got["reserved"] == 1
        assert got["available"] == 1
        # 预留令牌在重启后仍被保护：普通核销 409
        conflict = c2.post(
            f"/api/v1/chains/{cid}/redeem",
            json={"token_id": leaf, "request_key": "rsv-restart-rk",
                  "request_path": "/files/reports/x", "method": "GET"},
        )
        assert conflict.status_code == 409
        # 携带预留键核销成功，预留转为已用
        ok = c2.post(
            f"/api/v1/chains/{cid}/redeem",
            json={"token_id": leaf, "request_key": "rsv-restart-rk",
                  "request_path": "/files/reports/x", "method": "GET",
                  "reservation_key": "rsv-restart-1"},
        )
        assert ok.status_code == 201
        got2 = c2.get(f"/api/v1/subjects/{s}/redemption-quota").json()
        assert got2["used"] == 1 and got2["reserved"] == 0
