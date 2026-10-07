"""链末端 subject 的跨链成功核销总额度：设置 / 调整 / 查询、单链与会签扣减、
余额不足拒绝不占键、历史用量口径、并发不超发、重放不重复计数、重启口径不变。"""
from __future__ import annotations

import itertools
import threading
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
    root_subject: str | None = None,
    path: str = "/files/reports/x",
    allow_ip: str | None = None,
    leaf_secret: str | None = None,
) -> dict:
    """root -> leaf 的合法两级链（对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        f"{leaf_id}-root", None, "root", root_subject or leaf_issuer,
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


def _chain_with_tip_subject(client, subject: str) -> tuple[str, str]:
    """提交一条末端 subject 为 subject 的链，返回 (chain_id, leaf_token_id)。"""
    n = next(_chain_seq)
    chain_id, leaf_id = f"quota-chain-{n}", f"quota-leaf-{n}"
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


def _redeem(client, chain_id, token_id, request_key, *, path="/files/reports/x",
            method="GET", source_ip=None, body=None):
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
    return client.post(f"/api/v1/chains/{chain_id}/redeem", json=payload)


def _co_redeem(client, primary, review, request_key, *,
               path="/files/reports/x", source_ip="10.1.2.3"):
    payload = {
        "primary": {"chain_id": primary[0], "token_id": primary[1]},
        "review": {"chain_id": review[0], "token_id": review[1]},
        "request_key": request_key,
        "request_path": path,
        "method": "GET",
        "source_ip": source_ip,
    }
    return client.post("/api/v1/co-redemptions", json=payload)


# --------------------------------------------------------------------------- #
# 查询 / 设置 / 调整
# --------------------------------------------------------------------------- #
def test_unset_quota_is_unlimited(client):
    resp = _get_quota(client, "nobody")
    assert resp.status_code == 200
    data = resp.json()
    assert data["subject"] == "nobody"
    assert data["limit"] is None
    assert data["remaining"] is None
    assert data["used"] == 0
    assert data["updated_at"] is None
    assert data["previous_limit"] is None


def test_set_quota_returns_limit_used_remaining_and_previous(client):
    s = _subj("alice")
    resp = _set_quota(client, s, 3)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["subject"] == s
    assert data["limit"] == 3
    assert data["used"] == 0
    assert data["remaining"] == 3
    assert data["previous_limit"] is None
    assert data["updated_at"] is not None

    again = _set_quota(client, s, 5)
    assert again.status_code == 200
    assert again.json()["previous_limit"] == 3
    assert again.json()["limit"] == 5
    assert again.json()["remaining"] == 5


def test_negative_limit_rejected_422(client):
    s = _subj("alice")
    resp = _set_quota(client, s, -1)
    assert resp.status_code == 422


def test_clear_quota_with_null_restores_unlimited(client):
    s = _subj("alice")
    assert _set_quota(client, s, 1).status_code == 200
    cleared = _set_quota(client, s, None)
    assert cleared.status_code == 200
    data = cleared.json()
    assert data["limit"] is None
    assert data["remaining"] is None
    assert data["previous_limit"] == 1
    # 清除后不随用量受限
    cid, leaf = _chain_with_tip_subject(client, s)
    ok = _redeem(client, cid, leaf, "quota-clear-rk")
    assert ok.status_code == 201
    got = _get_quota(client, s).json()
    assert got["limit"] is None and got["used"] == 1


def test_lower_quota_below_used_conflicts_and_keeps_old_limit(client):
    s = _subj("bob")
    c1, l1 = _chain_with_tip_subject(client, s)
    assert _redeem(client, c1, l1, "quota-low-1").status_code == 201
    assert _set_quota(client, s, 2).status_code == 200

    resp = _set_quota(client, s, 0)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["subject"] == s
    assert detail["requested_limit"] == 0
    assert detail["used"] == 1
    assert detail["limit"] == 2
    assert detail["remaining"] == 1

    # 原额度未被改动：调低失败不影响核销
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _redeem(client, c2, l2, "quota-low-2").status_code == 201
    # 已用 2，再设 1 仍被拒绝；设 2 可以（不低于已用量）
    assert _set_quota(client, s, 1).status_code == 409
    assert _set_quota(client, s, 2).status_code == 200


def test_quota_set_to_zero_blocks_all_redemptions_when_unused(client):
    s = _subj("carol")
    assert _set_quota(client, s, 0).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    resp = _redeem(client, cid, leaf, "quota-zero-rk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["decision"] == "allow"
    assert data["deny_reason"] == "quota_exhausted"
    assert data["quota"] == {
        "subject": s,
        "limit": 0,
        "used": 0,
        "reserved": 0,
        "remaining": 0,
        "available": 0,
        "updated_at": data["quota"]["updated_at"],
    }
    # 令牌与 request_key 均未被消耗
    assert client.get(f"/api/v1/chains/{cid}").json()["redemptions"] == []


# --------------------------------------------------------------------------- #
# 单链核销扣减 / 余额不足 / 不占键 / 重放不重复计数
# --------------------------------------------------------------------------- #
def test_single_redemptions_deduct_until_exhausted_then_deny_without_key(client):
    s = _subj("dave")
    assert _set_quota(client, s, 2).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    c2, l2 = _chain_with_tip_subject(client, s)
    c3, l3 = _chain_with_tip_subject(client, s)

    r1 = _redeem(client, c1, l1, "quota-dave-1")
    assert r1.status_code == 201
    assert r1.json()["quota"]["used"] == 1
    assert r1.json()["quota"]["remaining"] == 1

    r2 = _redeem(client, c2, l2, "quota-dave-2")
    assert r2.status_code == 201
    assert r2.json()["quota"]["used"] == 2
    assert r2.json()["quota"]["remaining"] == 0

    # 第三次：余额不足明确拒绝，不核销、不占用 request_key
    r3 = _redeem(client, c3, l3, "quota-dave-3")
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["redeemed"] is False
    assert d3["decision"] == "allow"
    assert d3["deny_reason"] == "quota_exhausted"
    assert d3["quota"]["used"] == 2 and d3["quota"]["remaining"] == 0

    # 调高额度后同一把 request_key 成功（之前不占键）
    assert _set_quota(client, s, 3).status_code == 200
    r3b = _redeem(client, c3, l3, "quota-dave-3")
    assert r3b.status_code == 201
    assert r3b.json()["quota"]["used"] == 3
    assert r3b.json()["quota"]["remaining"] == 0

    # 口径查询与之一致
    got = _get_quota(client, s).json()
    assert got["limit"] == 3 and got["used"] == 3 and got["remaining"] == 0


def test_usage_includes_successful_redemptions_before_quota_was_set(client):
    s = _subj("erin")
    c1, l1 = _chain_with_tip_subject(client, s)
    assert _redeem(client, c1, l1, "quota-pre-1").status_code == 201
    # 设置前已有 1 次成功单链核销：设置额度时即计入已用量
    resp = _set_quota(client, s, 1)
    assert resp.status_code == 200
    data = resp.json()
    assert data["used"] == 1 and data["remaining"] == 0

    c2, l2 = _chain_with_tip_subject(client, s)
    denied = _redeem(client, c2, l2, "quota-pre-2")
    assert denied.status_code == 200
    assert denied.json()["deny_reason"] == "quota_exhausted"
    assert _get_quota(client, s).json()["used"] == 1


def test_authorization_denial_does_not_check_quota_or_consume(client):
    s = _subj("frank")
    assert _set_quota(client, s, 0).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    # 方法不允许 -> 既有授权判定拒绝：按约定不检查余额，响应不带 quota
    resp = _redeem(client, cid, leaf, "quota-auth-rk", method="POST")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["decision"] == "deny"
    assert data["first_failed_reason"] == "method_not_allowed"
    assert data["deny_reason"] is None
    assert data["quota"] is None
    # 失败不计数
    assert _get_quota(client, s).json()["used"] == 0


def test_successful_replay_preserves_first_quota_snapshot_and_counts_once(client):
    s = _subj("gina")
    assert _set_quota(client, s, 2).status_code == 200
    c1, l1 = _chain_with_tip_subject(client, s)
    first = _redeem(client, c1, l1, "quota-replay-rk")
    assert first.status_code == 201
    assert first.json()["quota"]["used"] == 1

    # 另一笔把额度用满
    c2, l2 = _chain_with_tip_subject(client, s)
    assert _redeem(client, c2, l2, "quota-replay-other").status_code == 201

    # 同键同内容重放：保留首次结果（含首次口径 used=1），不重复计数
    replay = _redeem(client, c1, l1, "quota-replay-rk")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["redeemed"] is True
    assert body["quota"]["used"] == 1
    assert body["quota"]["remaining"] == 1
    assert _get_quota(client, s).json()["used"] == 2


def test_revocation_after_success_does_not_refund_usage(client):
    s = _subj("hank")
    assert _set_quota(client, s, 1).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _redeem(client, cid, leaf, "quota-revoke-rk").status_code == 201

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post(
        f"/api/v1/chains/{cid}/revocations",
        json={"token_id": leaf, "effective_at": now,
              "reason": "追溯撤销不退还用量", "request_key": "quota-revoke-op"},
    ).status_code == 201

    got = _get_quota(client, s).json()
    assert got["used"] == 1 and got["remaining"] == 0
    # 已用量不退还：额度不能调到 0
    assert _set_quota(client, s, 0).status_code == 409


def test_key_deactivation_after_success_does_not_refund_usage(client):
    s = _subj("lois")
    # 专用签发主体，避免停用共享的 svc-a 影响其他用例
    issuer = s + "-issuer"
    assert client.post(
        "/api/v1/principals",
        json={"name": issuer, "hmac_secret": "lois-issuer-secret-v1"},
    ).status_code == 201
    n = next(_chain_seq)
    chain_id, leaf_id = f"quota-kd-{n}", f"quota-kd-leaf-{n}"
    chain = _two_token_chain(
        chain_id, leaf_id, s, leaf_issuer=issuer,
        leaf_secret="lois-issuer-secret-v1",
    )
    assert client.post("/api/v1/chains", json=chain).status_code == 201

    assert _set_quota(client, s, 1).status_code == 200
    assert _redeem(client, chain_id, leaf_id, "quota-kd-rk").status_code == 201

    # 停用该签发主体的第 1 代密钥：历史成功核销不改写、用量不退还
    deact = client.post(
        f"/api/v1/principals/{issuer}/generations/1/deactivate-key",
        json={"reason": "疑似密钥失陷：验证停用不退还历史额度用量"},
    )
    assert deact.status_code == 201

    got = _get_quota(client, s).json()
    assert got["used"] == 1 and got["limit"] == 1 and got["remaining"] == 0
    # 成功请求同键重放仍保留首次结果、不重复计数
    replay = _redeem(client, chain_id, leaf_id, "quota-kd-rk")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert _get_quota(client, s).json()["used"] == 1
    # 额度仍不得低于已用量
    assert _set_quota(client, s, 0).status_code == 409


def test_quota_survives_restart_with_same_semantics(client):
    s = _subj("ivan")
    assert _set_quota(client, s, 2).status_code == 200
    cid, leaf = _chain_with_tip_subject(client, s)
    assert _redeem(client, cid, leaf, "quota-restart-rk").status_code == 201

    # 模拟重启：同一数据库文件上重新进入应用生命周期
    with TestClient(app) as c2:
        got = c2.get(f"/api/v1/subjects/{s}/redemption-quota").json()
        assert got["limit"] == 2 and got["used"] == 1 and got["remaining"] == 1

        cid2, leaf2 = _chain_with_tip_subject(c2, s)
        ok = c2.post(
            f"/api/v1/chains/{cid2}/redeem",
            json={"token_id": leaf2, "request_key": "quota-restart-rk-2",
                  "request_path": "/files/reports/x", "method": "GET"},
        )
        assert ok.status_code == 201

        cid3, leaf3 = _chain_with_tip_subject(c2, s)
        denied = c2.post(
            f"/api/v1/chains/{cid3}/redeem",
            json={"token_id": leaf3, "request_key": "quota-restart-rk-3",
                  "request_path": "/files/reports/x", "method": "GET"},
        )
        assert denied.status_code == 200
        assert denied.json()["deny_reason"] == "quota_exhausted"


# --------------------------------------------------------------------------- #
# 并发不超发
# --------------------------------------------------------------------------- #
def test_concurrent_single_redemptions_never_exceed_quota(client):
    s = _subj("judy")
    assert _set_quota(client, s, 1).status_code == 200
    targets = [_chain_with_tip_subject(client, s) for _ in range(8)]
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        cid, leaf = targets[i]
        resp = _redeem(client, cid, leaf, f"quota-conc-{i}")
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
    assert got["used"] == 1 and got["remaining"] == 0


def test_concurrent_redemptions_and_quota_adjustment_do_not_overshoot(client):
    s = _subj("kyle")
    # 初始额度 1：8 笔并发核销与“调高到 2”并发，成功数只能是 1 或 2，绝不超发
    assert _set_quota(client, s, 1).status_code == 200
    targets = [_chain_with_tip_subject(client, s) for _ in range(8)]
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(9)

    def redeem_worker(i: int) -> None:
        barrier.wait()
        cid, leaf = targets[i]
        resp = _redeem(client, cid, leaf, f"quota-mix-{i}")
        results.append((resp.status_code, resp.json()))

    def adjust_worker() -> None:
        barrier.wait()
        _set_quota(client, s, 2)

    threads = [threading.Thread(target=redeem_worker, args=(i,)) for i in range(8)]
    threads.append(threading.Thread(target=adjust_worker))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0] == 201]
    assert 1 <= len(created) <= 2
    # 最终口径自洽：已用量 == 实际成功数，且不超过最终额度
    got = _get_quota(client, s).json()
    assert got["limit"] == 2
    assert got["used"] == len(created)
    assert got["used"] <= got["limit"]


# --------------------------------------------------------------------------- #
# 会签：每侧主体各计一次；任一侧余额不足两侧均不核销、不占键
# --------------------------------------------------------------------------- #
def _co_pair(client, primary_subject=None, review_subject=None):
    """提交一对会签链，返回 ((primary_chain, leaf), (review_chain, leaf), psub, rsub)。

    主体名默认按对唯一，避免会话级共享数据库中其他测试文件的 alice/bob 用量串入。
    """
    n = next(_chain_seq)
    psub = primary_subject or f"qpa-{n}"
    rsub = review_subject or f"qpr-{n}"
    primary = _two_token_chain(
        f"quota-co-p-{n}", f"quota-co-pl-{n}", psub, "svc-a",
        allow_ip="10.1.0.0/16",
    )
    review = _two_token_chain(
        f"quota-co-r-{n}", f"quota-co-rl-{n}", rsub, "svc-b",
        allow_ip="10.1.0.0/16",
    )
    assert client.post("/api/v1/chains", json=primary).status_code == 201
    assert client.post("/api/v1/chains", json=review).status_code == 201
    return (
        (f"quota-co-p-{n}", f"quota-co-pl-{n}"),
        (f"quota-co-r-{n}", f"quota-co-rl-{n}"),
        psub,
        rsub,
    )


def test_co_redemption_counts_once_for_each_participating_subject(client):
    primary, review, psub, rsub = _co_pair(client, "alice-quota-1", "bob-quota-1")
    assert _set_quota(client, psub, 2).status_code == 200
    resp = _co_redeem(client, primary, review, "quota-co-ok")
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["primary"]["subject"] == psub
    # 设置了额度的一侧返回扣减后口径；未设置的一侧 quota 为 null（不限额）
    assert data["primary"]["quota"]["used"] == 1
    assert data["primary"]["quota"]["remaining"] == 1
    assert data["review"]["quota"] is None

    assert _get_quota(client, psub).json()["used"] == 1
    assert _get_quota(client, rsub).json()["used"] == 1
    assert _get_quota(client, rsub).json()["limit"] is None


def test_co_redemption_one_side_exhausted_redeems_neither_and_keeps_key(client):
    primary, review, psub, rsub = _co_pair(client, "alice-quota-2", "bob-quota-2")
    assert _set_quota(client, psub, 0).status_code == 200
    resp = _co_redeem(client, primary, review, "quota-co-denied")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["redeemed"] is False
    assert data["redeemed_at"] is None
    assert data["primary"]["decision"] == "deny"
    assert data["primary"]["deny_reason"] == "quota_exhausted"
    assert data["primary"]["quota"]["remaining"] == 0
    # 复核侧既有判定允许，额度未设置（不进行余额限制）
    assert data["review"]["decision"] == "allow"
    assert data["review"]["deny_reason"] is None

    # 两侧均不核销、不计数
    assert _get_quota(client, psub).json()["used"] == 0
    assert _get_quota(client, rsub).json()["used"] == 0
    assert client.get(
        f"/api/v1/chains/{review[0]}"
    ).json()["redemptions"] == []

    # 调高额度后同一把 request_key 会签成功
    assert _set_quota(client, psub, 1).status_code == 200
    ok = _co_redeem(client, primary, review, "quota-co-denied")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True
    assert _get_quota(client, psub).json()["used"] == 1
    assert _get_quota(client, rsub).json()["used"] == 1


def test_co_redeem_consumes_subject_quota_shared_with_single_redemptions(client):
    # 主授权侧主体额度 1：会签用过一次后，该主体另一链的单链核销被余额拒绝
    primary, review, psub, _ = _co_pair(
        client, "alice-quota-3", "bob-quota-3"
    )
    assert _set_quota(client, psub, 1).status_code == 200
    assert _co_redeem(client, primary, review, "quota-co-share").status_code == 201

    cid, leaf = _chain_with_tip_subject(client, psub)
    denied = _redeem(client, cid, leaf, "quota-co-single-after")
    assert denied.status_code == 200
    assert denied.json()["deny_reason"] == "quota_exhausted"
    assert _get_quota(client, psub).json()["used"] == 1


def test_co_redeem_authorization_denial_skips_quota_checks(client):
    # 即使主授权侧主体额度为 0，一侧授权拒绝时根本不进入余额检查：
    # 两侧 leg.quota 均为 None，拒绝原因是授权原因而非余额
    primary, review, psub, _ = _co_pair(client, "alice-quota-4", "bob-quota-4")
    assert _set_quota(client, psub, 0).status_code == 200
    resp = _co_redeem(client, primary, review, "quota-co-auth",
                      source_ip="192.168.0.1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    for side in ("primary", "review"):
        assert data[side]["decision"] == "deny"
        assert data[side]["deny_reason"] is None
        assert data[side]["quota"] is None
    assert _get_quota(client, psub).json()["used"] == 0


def test_co_redeem_replay_does_not_recount_and_keeps_snapshot(client):
    primary, review, psub, rsub = _co_pair(client, "alice-quota-5", "bob-quota-5")
    assert _set_quota(client, psub, 2).status_code == 200
    first = _co_redeem(client, primary, review, "quota-co-replay")
    assert first.status_code == 201
    replay = _co_redeem(client, primary, review, "quota-co-replay")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["primary"]["quota"]["used"] == 1
    assert body["primary"]["quota"]["remaining"] == 1
    assert _get_quota(client, psub).json()["used"] == 1
    assert _get_quota(client, rsub).json()["used"] == 1


def test_concurrent_co_redemptions_never_exceed_quota(client):
    # 主授权侧总额度 2：4 对不同末端并发会签，仅 2 笔成功
    pairs = []
    psub = "alice-quota-6"
    rsub = "bob-quota-6"
    for _ in range(4):
        pairs.append(_co_pair(client, psub, rsub)[:2])
    assert _set_quota(client, psub, 2).status_code == 200
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(4)

    def worker(i: int) -> None:
        barrier.wait()
        primary, review = pairs[i]
        resp = _co_redeem(client, primary, review, f"quota-co-conc-{i}")
        results.append((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0] == 201]
    exhausted = [
        r for r in results
        if r[0] == 200 and r[1]["primary"].get("deny_reason") == "quota_exhausted"
    ]
    assert len(created) == 2
    assert len(exhausted) == 2
    got = _get_quota(client, psub).json()
    assert got["used"] == 2 and got["remaining"] == 0
    # 余额不足的会签两侧都不核销：复核侧只参与了成功的 2 笔
    assert _get_quota(client, rsub).json()["used"] == 2


def test_co_subject_participating_twice_counts_twice(client):
    # 同一主体在两笔不同会签中各参与一次：每次算一次，共 2
    psub, rsub = "alice-quota-7", "bob-quota-7"
    p1, r1, _, _ = _co_pair(client, psub, rsub)
    p2, r2, _, _ = _co_pair(client, psub, rsub)
    assert _set_quota(client, psub, 2).status_code == 200
    assert _co_redeem(client, p1, r1, "quota-co-twice-1").status_code == 201
    assert _co_redeem(client, p2, r2, "quota-co-twice-2").status_code == 201
    got = _get_quota(client, psub).json()
    assert got["used"] == 2 and got["remaining"] == 0
