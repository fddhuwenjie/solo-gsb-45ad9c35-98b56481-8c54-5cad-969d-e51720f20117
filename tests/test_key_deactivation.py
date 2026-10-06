"""疑似失陷签发密钥停用：按主体 + 代次停用，立即生效、不可撤销，轮换不解除。

覆盖：
- 停用端点契约（201 / 幂等 200 / 换原因 409 / 主体或代次 404 / 非法代次 422）；
- 已提交链在只读求值、首次单链核销、双链会签中从对应签发节点拒绝，轨迹标明
  ``key_deactivated``；只读求值不能用过去时刻绕过；会签一侧拒绝时另一侧不消耗；
- 停用当前代次：新提交链保存原代次归属与拒绝结论，同内容重放返回原结论；
- 轮换后新代次签发的链正常；历史链提交报告与已完成核销记录不改写；
- 停用与链提交 / 核销并发时，归属与判定对应一致的已提交状态。
"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_principal_seq = itertools.count(1)
_chain_seq = itertools.count(1)


def _now_window() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    na = (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
    return nb, na


def _new_principal(client, secret: str | None = None) -> tuple[str, str]:
    name = f"kd-svc-{next(_principal_seq)}"
    secret = secret or f"{name}-secret-v1"
    resp = client.post(
        "/api/v1/principals", json={"name": name, "hmac_secret": secret}
    )
    assert resp.status_code == 201, resp.text
    return name, secret


def _rotate(client, name: str, new_secret: str):
    return client.post(
        f"/api/v1/principals/{name}/rotate-key",
        json={"hmac_secret": new_secret},
    )


def _deactivate(client, name: str, generation: int, reason: str = "疑似密钥失陷"):
    return client.post(
        f"/api/v1/principals/{name}/generations/{generation}/deactivate-key",
        json={"reason": reason},
    )


def _chain2(chain_id: str, issuer: str, issuer_secret: str) -> dict:
    """root -> child 两级链；child 由 issuer 用 issuer_secret 签名（当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        "root", None, "root", issuer,
        "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    child = make_token(
        "child", "root", issuer, "kd-worker",
        "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
        secret=issuer_secret,
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


def _submit(client, issuer: str, issuer_secret: str):
    chain_id = f"chain-kd-{next(_chain_seq)}"
    payload = _chain2(chain_id, issuer, issuer_secret)
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    return chain_id, payload, resp.json()


def _evaluate(client, chain_id: str, at: str | None = None):
    at = at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={"request_path": "/files/x", "method": "GET", "at": at},
    )


def _redeem(client, chain_id: str, request_key: str):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "child",
            "request_key": request_key,
            "request_path": "/files/x",
            "method": "GET",
        },
    )


def _checks_by_id(result: dict) -> dict[str, dict[str, dict]]:
    return {
        node["token_id"]: {c["name"]: c for c in node["checks"]}
        for node in result["trace"]
    }


# --------------------------------------------------------------------------- #
# 停用端点契约
# --------------------------------------------------------------------------- #
def test_deactivate_success_immediate_and_leaks_no_secret(client):
    name, secret = _new_principal(client)
    resp = _deactivate(client, name, 1, reason="运维事件：怀疑密钥泄露")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["replayed"] is False
    event = body["event"]
    assert event["principal"] == name
    assert event["generation"] == 1
    assert event["reason"] == "运维事件：怀疑密钥泄露"
    assert event["deactivated_at"]
    assert secret not in resp.text


def test_deactivate_is_idempotent_same_reason(client):
    name, _ = _new_principal(client)
    first = _deactivate(client, name, 1, reason="同一原因")
    assert first.status_code == 201
    first_at = first.json()["event"]["deactivated_at"]

    second = _deactivate(client, name, 1, reason="同一原因")
    assert second.status_code == 200
    body = second.json()
    assert body["replayed"] is True
    assert body["event"]["deactivated_at"] == first_at


def test_deactivate_different_reason_conflicts_and_keeps_original(client):
    name, _ = _new_principal(client)
    assert _deactivate(client, name, 1, reason="原始原因").status_code == 201

    conflict = _deactivate(client, name, 1, reason="想改写的原因")
    assert conflict.status_code == 409
    detail = conflict.json()["detail"]
    assert detail["principal"] == name
    assert detail["generation"] == 1
    assert detail["existing_reason"] == "原始原因"
    assert detail["received_reason"] == "想改写的原因"

    # 再次以原原因重放仍返回原事件——停用不可改写
    replay = _deactivate(client, name, 1, reason="原始原因")
    assert replay.status_code == 200
    assert replay.json()["event"]["reason"] == "原始原因"


def test_deactivate_unknown_principal_404(client):
    resp = _deactivate(client, "kd-no-such-principal", 1)
    assert resp.status_code == 404
    assert "kd-no-such-principal" in resp.json()["detail"]


def test_deactivate_unknown_generation_404(client):
    name, _ = _new_principal(client)
    assert _deactivate(client, name, 2).status_code == 404
    assert _deactivate(client, name, 99).status_code == 404


def test_deactivate_non_positive_generation_422(client):
    name, _ = _new_principal(client)
    resp = client.post(
        f"/api/v1/principals/{name}/generations/0/deactivate-key",
        json={"reason": "x"},
    )
    assert resp.status_code == 422


def test_deactivate_empty_reason_422(client):
    name, _ = _new_principal(client)
    resp = client.post(
        f"/api/v1/principals/{name}/generations/1/deactivate-key",
        json={"reason": ""},
    )
    assert resp.status_code == 422


def test_deactivate_independent_generations_do_not_affect_each_other(client):
    name, secret_v1 = _new_principal(client)
    secret_v2 = f"{name}-secret-v2"
    assert _rotate(client, name, secret_v2).status_code == 200

    # 只停用第 1 代：第 2 代（当前代）仍可正常签发新链
    assert _deactivate(client, name, 1).status_code == 201
    chain_id, _, submitted = _submit(client, name, secret_v2)
    assert submitted["integrity"]["allow"] is True
    assert _evaluate(client, chain_id).json()["decision"] == "allow"


# --------------------------------------------------------------------------- #
# 已提交且绑定被停用代次的链：求值 / 核销 / 会签从签发节点拒绝
# --------------------------------------------------------------------------- #
def test_existing_chain_denied_in_evaluate_after_generation_deactivated(client):
    name, secret = _new_principal(client)
    chain_id, _, submitted = _submit(client, name, secret)
    assert submitted["integrity"]["allow"] is True

    assert _deactivate(client, name, 1).status_code == 201

    result = _evaluate(client, chain_id).json()
    assert result["decision"] == "deny"
    # root 由 root 主体签发（未停用），child 由被停用的 name 签发 -> child 先失败
    assert result["first_failed_node"] == "child"
    assert result["first_failed_reason"] == "key_deactivated"

    checks = _checks_by_id(result)
    child_key = checks["child"]["key_active"]
    assert child_key["passed"] is False
    assert child_key["reason"] == "key_deactivated"
    assert "疑似密钥失陷" in child_key["detail"] or "失陷" in child_key["detail"]
    # 签名本身仍然通过——拒绝纯粹来自密钥停用
    assert checks["child"]["signature"]["passed"] is True
    assert checks["root"]["key_active"]["passed"] is True


def test_evaluate_cannot_bypass_deactivation_with_past_time(client):
    name, secret = _new_principal(client)
    chain_id, _, _ = _submit(client, name, secret)
    assert _deactivate(client, name, 1).status_code == 201

    # 把请求时间指定到“过去”（仍落在链有效期内、停用之前）仍须拒绝：
    # 停用不是按请求时间解释的撤销事件
    past = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat().replace(
        "+00:00", "Z"
    )
    result = _evaluate(client, chain_id, at=past).json()
    assert result["decision"] == "deny"
    assert result["first_failed_reason"] == "key_deactivated"


def test_first_redeem_denied_after_deactivation_and_does_not_consume(client):
    name, secret = _new_principal(client)
    chain_id, _, _ = _submit(client, name, secret)
    assert _deactivate(client, name, 1).status_code == 201

    denied = _redeem(client, chain_id, "kd-rk-1")
    assert denied.status_code == 200
    body = denied.json()
    assert body["redeemed"] is False
    assert body["decision"] == "deny"
    assert body["first_failed_reason"] == "key_deactivated"

    # 链查询没有任何核销记录：拒绝不核销
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["redemptions"] == []

    # 轮换不能解除旧代次停用：之后再试仍被拒绝
    assert _rotate(client, name, f"{name}-secret-v2").status_code == 200
    again = _redeem(client, chain_id, "kd-rk-1")
    assert again.status_code == 200
    assert again.json()["redeemed"] is False
    assert again.json()["first_failed_reason"] == "key_deactivated"


def test_deactivating_current_generation_new_chain_stores_attribution_and_denial(client):
    name, secret = _new_principal(client)
    assert _deactivate(client, name, 1).status_code == 201

    # 停用的就是当前代（第 1 代）：用该代密钥签出的新链仍保存代次归属，
    # 提交报告即以 key_deactivated 拒绝
    chain_id, payload, submitted = _submit(client, name, secret)
    integrity = submitted["integrity"]
    assert integrity["allow"] is False
    assert integrity["first_failed_node"] == "child"
    assert integrity["first_failed_reason"] == "key_deactivated"

    # 归属仍记录为原（当前）代次第 1 代：停用不删除代次历史，链查询 / 求值
    # 始终按该归属命中停用（轮换到新代次后，该旧链仍绑定第 1 代、仍被拒绝）
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["integrity"]["first_failed_reason"] == "key_deactivated"

    # 同内容重放返回原完整性结论（不翻转、不改写）
    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["integrity"]["first_failed_reason"] == "key_deactivated"

    # 只读求值同样拒绝
    assert _evaluate(client, chain_id).json()["first_failed_reason"] == "key_deactivated"


def test_rotation_after_deactivation_new_generation_chain_works_normally(client):
    name, secret_v1 = _new_principal(client)
    old_chain, _, _ = _submit(client, name, secret_v1)
    assert _deactivate(client, name, 1).status_code == 201
    secret_v2 = f"{name}-secret-v2"
    assert _rotate(client, name, secret_v2).status_code == 200

    # 轮换不解除停用：历史链继续拒绝
    assert _evaluate(client, old_chain).json()["first_failed_reason"] == "key_deactivated"

    # 新代次签发的链正常验签、求值、核销
    new_chain, _, new_submitted = _submit(client, name, secret_v2)
    assert new_submitted["integrity"]["allow"] is True
    assert _evaluate(client, new_chain).json()["decision"] == "allow"
    redeemed = _redeem(client, new_chain, "kd-rk-new")
    assert redeemed.status_code == 201
    assert redeemed.json()["redeemed"] is True

    # 停用第 2 代不影响第 1 代已停用之外的判定逻辑（此处第 2 代新链随即拒绝）
    assert _deactivate(client, name, 2).status_code == 201
    assert _evaluate(client, new_chain).json()["first_failed_reason"] == "key_deactivated"


def test_historical_submission_report_and_completed_redemption_not_rewritten(client):
    name, secret = _new_principal(client)
    chain_id, _, _ = _submit(client, name, secret)

    # 停用前完成一次核销
    first = _redeem(client, chain_id, "kd-rk-hist")
    assert first.status_code == 201
    first_body = first.json()
    first_redeemed_at = first_body["redeemed_at"]

    assert _deactivate(client, name, 1).status_code == 201

    # 历史链的提交时完整性报告不改写（GET 仍返回 allow）
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["integrity"]["allow"] is True

    # 已完成核销记录不改写，仍可在链查询中看到
    assert len(got["redemptions"]) == 1
    assert got["redemptions"][0]["request_key"] == "kd-rk-hist"

    # 已成功核销的同键同内容重放仍返回首次结果（停用不影响）
    replay = _redeem(client, chain_id, "kd-rk-hist")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["redeemed"] is True
    assert body["decision"] == "allow"
    assert body["redeemed_at"] == first_redeemed_at


# --------------------------------------------------------------------------- #
# 双链会签：任一侧密钥停用 -> 拒绝且另一侧不被消耗
# --------------------------------------------------------------------------- #
def _review_chain(client, chain_id: str, issuer: str, issuer_secret: str,
                  leaf_id: str, tip_subject: str) -> dict:
    nb, na = _now_window()
    root = make_token(
        f"{leaf_id}-root", None, "root", issuer,
        "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    leaf = make_token(
        leaf_id, f"{leaf_id}-root", issuer, tip_subject,
        "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
        secret=issuer_secret,
    )
    payload = {"chain_id": chain_id, "tokens": [root, leaf]}
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    return payload


def _co_redeem(client, primary_chain: str, primary_leaf: str,
               review_chain: str, review_leaf: str, request_key: str):
    return client.post(
        "/api/v1/co-redemptions",
        json={
            "primary": {"chain_id": primary_chain, "token_id": primary_leaf},
            "review": {"chain_id": review_chain, "token_id": review_leaf},
            "request_key": request_key,
            "request_path": "/files/x",
            "method": "GET",
        },
    )


def test_co_redemption_denied_when_one_side_key_deactivated_other_not_consumed(client):
    p_name, p_secret = _new_principal(client)
    r_name, r_secret = _new_principal(client)

    p_chain = f"chain-kd-co-p-{next(_chain_seq)}"
    r_chain = f"chain-kd-co-r-{next(_chain_seq)}"
    _review_chain(client, p_chain, p_name, p_secret, "p-leaf", "kd-worker-p")
    _review_chain(client, r_chain, r_name, r_secret, "r-leaf", "kd-worker-r")

    # 只停用主授权侧的签发密钥
    assert _deactivate(client, p_name, 1).status_code == 201

    resp = _co_redeem(client, p_chain, "p-leaf", r_chain, "r-leaf", "kd-co-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["redeemed"] is False
    assert body["primary"]["decision"] == "deny"
    assert body["primary"]["first_failed_reason"] == "key_deactivated"
    # 复核侧本身仍然 allow（轨迹标明停用检查通过）
    assert body["review"]["decision"] == "allow"

    # 两侧都没有核销记录、request_key 未占用
    assert client.get(f"/api/v1/chains/{p_chain}").json()["redemptions"] == []
    assert client.get(f"/api/v1/chains/{r_chain}").json()["redemptions"] == []

    # 解除主授权侧问题的办法只能是换用未停用代次签发的新链；
    # 这里复核侧仍可独立用于另一次会签（不被消耗）。轮换主授权主体到新代次，
    # 用新代次签发新主授权链后，会签用同一 request_key 可成功（键未被占用）。
    assert _rotate(client, p_name, f"{p_name}-secret-v2").status_code == 200
    p_chain2 = f"chain-kd-co-p2-{next(_chain_seq)}"
    _review_chain(client, p_chain2, p_name, f"{p_name}-secret-v2",
                  "p-leaf2", "kd-worker-p2")
    ok = _co_redeem(client, p_chain2, "p-leaf2", r_chain, "r-leaf", "kd-co-1")
    assert ok.status_code == 201, ok.text
    assert ok.json()["redeemed"] is True

    # 原复核链只参与了成功的那次会签；原主授权链始终无核销
    assert client.get(f"/api/v1/chains/{p_chain}").json()["redemptions"] == []
    assert len(client.get(f"/api/v1/chains/{r_chain}").json()["redemptions"]) == 1


def test_co_redemption_both_sides_deactivated_both_denied(client):
    p_name, p_secret = _new_principal(client)
    r_name, r_secret = _new_principal(client)
    p_chain = f"chain-kd-co-p-{next(_chain_seq)}"
    r_chain = f"chain-kd-co-r-{next(_chain_seq)}"
    _review_chain(client, p_chain, p_name, p_secret, "p-leaf", "kd-worker-p")
    _review_chain(client, r_chain, r_name, r_secret, "r-leaf", "kd-worker-r")

    assert _deactivate(client, p_name, 1).status_code == 201
    assert _deactivate(client, r_name, 1).status_code == 201

    resp = _co_redeem(client, p_chain, "p-leaf", r_chain, "r-leaf", "kd-co-both")
    assert resp.status_code == 200
    body = resp.json()
    assert body["redeemed"] is False
    assert body["primary"]["first_failed_reason"] == "key_deactivated"
    assert body["review"]["first_failed_reason"] == "key_deactivated"
    assert client.get(f"/api/v1/chains/{p_chain}").json()["redemptions"] == []
    assert client.get(f"/api/v1/chains/{r_chain}").json()["redemptions"] == []


def test_successful_co_redemption_replay_unchanged_after_deactivation(client):
    p_name, p_secret = _new_principal(client)
    r_name, r_secret = _new_principal(client)
    p_chain = f"chain-kd-co-p-{next(_chain_seq)}"
    r_chain = f"chain-kd-co-r-{next(_chain_seq)}"
    _review_chain(client, p_chain, p_name, p_secret, "p-leaf", "kd-worker-p")
    _review_chain(client, r_chain, r_name, r_secret, "r-leaf", "kd-worker-r")

    first = _co_redeem(client, p_chain, "p-leaf", r_chain, "r-leaf", "kd-co-done")
    assert first.status_code == 201
    first_body = first.json()

    # 事后停用两侧密钥
    assert _deactivate(client, p_name, 1).status_code == 201
    assert _deactivate(client, r_name, 1).status_code == 201

    replay = _co_redeem(client, p_chain, "p-leaf", r_chain, "r-leaf", "kd-co-done")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["redeemed"] is True
    assert body["redeemed_at"] == first_body["redeemed_at"]
    # 回放首次轨迹（首次为 allow），不停用不重算
    assert body["primary"]["decision"] == "allow"
    assert body["review"]["decision"] == "allow"


# --------------------------------------------------------------------------- #
# 未受影响链保持既有行为
# --------------------------------------------------------------------------- #
def test_unrelated_chain_unaffected_by_deactivation(client):
    hit_name, hit_secret = _new_principal(client)
    safe_name, safe_secret = _new_principal(client)

    hit_chain, _, _ = _submit(client, hit_name, hit_secret)
    safe_chain, _, _ = _submit(client, safe_name, safe_secret)

    assert _deactivate(client, hit_name, 1).status_code == 201

    assert _evaluate(client, hit_chain).json()["decision"] == "deny"
    safe_eval = _evaluate(client, safe_chain).json()
    assert safe_eval["decision"] == "allow"
    # 未受影响链的节点不出现 key_active 失败
    for node in safe_eval["trace"]:
        key_check = next((c for c in node["checks"] if c["name"] == "key_active"), None)
        assert key_check is None or key_check["passed"] is True

    # 未受影响链可正常核销
    assert _redeem(client, safe_chain, "kd-rk-safe").status_code == 201


def test_deactivation_does_not_change_revocation_semantics(client):
    """撤销（按请求时间解释）与密钥停用（与时间无关）正交。"""
    name, secret = _new_principal(client)
    chain_id, _, _ = _submit(client, name, secret)

    now = datetime.now(timezone.utc)
    future = (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    resp = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "child",
            "effective_at": future,
            "reason": "未来生效的撤销",
            "request_key": "kd-rev-1",
        },
    )
    assert resp.status_code == 201

    # 撤销尚未生效：无停用时此刻应 allow
    assert _evaluate(client, chain_id).json()["decision"] == "allow"

    # 停用密钥后：即使撤销仍未生效、即使请求时间取链有效期内的过去时刻，
    # 都因停用拒绝
    assert _deactivate(client, name, 1).status_code == 201
    past = (now - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    result = _evaluate(client, chain_id, at=past).json()
    assert result["decision"] == "deny"
    assert result["first_failed_reason"] == "key_deactivated"
    # 未来撤销在过去时刻不生效，故 first_revoked_node 为空
    assert result["first_revoked_node"] is None


# --------------------------------------------------------------------------- #
# 并发：停用与链提交 / 核销交错时，归属与判定对应一致的已提交状态
# --------------------------------------------------------------------------- #
def test_concurrent_duplicate_deactivation_same_reason_one_event(client):
    """并发停用同一（主体, 代次）同原因：一笔 201，其余幂等 200，事件唯一。"""
    name, _ = _new_principal(client)
    barrier = threading.Barrier(4)
    statuses: list[int] = []

    def deactivator() -> None:
        barrier.wait()
        resp = _deactivate(client, name, 1, reason="并发同一原因")
        statuses.append(resp.status_code)

    threads = [threading.Thread(target=deactivator) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(statuses) == [200, 200, 200, 201]

    # 只有一条停用事件：后续同原因仍是 200、同一 deactivated_at
    resp = _deactivate(client, name, 1, reason="并发同一原因")
    assert resp.status_code == 200
    assert resp.json()["replayed"] is True


def test_concurrent_deactivation_and_submission_attribution_consistent(client):
    name, secret_v1 = _new_principal(client)
    barrier = threading.Barrier(7)
    results: list[tuple[str, bool, str | None]] = []

    def submitter(i: int) -> None:
        chain_id = f"chain-kd-conc-{i}"
        payload = _chain2(chain_id, name, secret_v1)
        barrier.wait()
        resp = client.post("/api/v1/chains", json=payload)
        assert resp.status_code == 201, resp.text
        integrity = resp.json()["integrity"]
        results.append(
            (chain_id, integrity["allow"], integrity["first_failed_reason"])
        )

    threads = [threading.Thread(target=submitter, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    barrier.wait()  # 与 6 个提交并发执行停用
    deactivated = _deactivate(client, name, 1)
    assert deactivated.status_code == 201
    for t in threads:
        t.join()

    assert len(results) == 6
    for chain_id, allow, reason in results:
        # 无论提交落在停用前还是后，存储报告与实时求值的结论必须一致：
        # 提交时 allow 的链归属第 1 代，停用后实时求值转为 key_deactivated，
        # 但提交报告不改写；提交时已停用的链报告本身即 key_deactivated。
        got = client.get(f"/api/v1/chains/{chain_id}").json()
        assert got["integrity"]["allow"] is allow
        evaluated = _evaluate(client, chain_id).json()
        if allow:
            # 提交早于停用：提交报告仍 allow，但停用后求值一律拒绝
            assert reason is None
            assert evaluated["decision"] == "deny"
            assert evaluated["first_failed_reason"] == "key_deactivated"
        else:
            assert reason == "key_deactivated"
            assert evaluated["first_failed_reason"] == "key_deactivated"


def test_concurrent_deactivation_and_redeem_only_one_consistent_outcome(client):
    """停用与核销并发：要么在停用前核销成功（重放永远返回首次成功），
    要么观察到停用并拒绝（不核销）；不会出现“核销成功但记录结论矛盾”。"""
    name, secret = _new_principal(client)
    chain_id, _, _ = _submit(client, name, secret)
    barrier = threading.Barrier(2)
    outcomes: list[tuple[int, bool, bool, str | None]] = []

    def redeemer() -> None:
        barrier.wait()
        resp = _redeem(client, chain_id, "kd-rk-conc")
        body = resp.json()
        outcomes.append(
            (resp.status_code, body.get("redeemed", False),
             body.get("replayed", False), body.get("first_failed_reason"))
        )

    def deactivator() -> None:
        barrier.wait()
        _deactivate(client, name, 1)

    t1 = threading.Thread(target=redeemer)
    t2 = threading.Thread(target=deactivator)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(outcomes) == 1
    status_code, redeemed, _, reason = outcomes[0]
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    if redeemed:
        # 核销先于停用提交：201，记录存在；之后同键重放返回首次成功结果
        assert status_code == 201
        assert len(got["redemptions"]) == 1
        replay = _redeem(client, chain_id, "kd-rk-conc")
        assert replay.json()["replayed"] is True
        assert replay.json()["redeemed"] is True
        # 新 request_key 的核销尝试：令牌已核销 -> 409（停用与否都不可再核销）
        later = _redeem(client, chain_id, "kd-rk-conc-2")
        assert later.status_code == 409
        assert later.json()["detail"]["existing_request_key"] == "kd-rk-conc"
    else:
        # 停用先生效：拒绝且无记录
        assert status_code == 200
        assert reason == "key_deactivated"
        assert got["redemptions"] == []
        # request_key 未被占用，轮换到新代次也救不了旧链（代次仍绑定第 1 代）；
        # 但同一把键之后仍可用于一条新链的成功核销
        assert _rotate(client, name, f"{name}-secret-v2").status_code == 200
        new_chain, _, _ = _submit(client, name, f"{name}-secret-v2")
        ok = _redeem(client, new_chain, "kd-rk-conc")
        assert ok.status_code == 201
