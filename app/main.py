"""FastAPI 应用：提交能力链、幂等重放、冲突检测、撤销审计、请求级判定、一次性核销、双主体会签、密钥轮换与短时额度预留。"""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from .database import (
    compute_revocation_impacts,
    delete_reservation,
    get_conn,
    get_db,
    get_principal_key_row,
    get_quota_status,
    get_secret_at_generation,
    init_db,
    insert_co_redemption,
    insert_key_deactivation,
    insert_redemption,
    insert_reservation,
    insert_revocation,
    insert_revocation_impacts,
    install_next_key_generation,
    key_generation_exists,
    load_chain_key_generations,
    load_chain_missing_issuers,
    load_chain_record,
    load_co_redemption_by_request_key,
    load_deactivated_keys,
    load_key_deactivation,
    load_redemption_by_request_key,
    load_redemption_for_token,
    load_redemptions,
    load_reservation_by_key,
    load_reservation_for_token,
    load_revocation_by_request_key,
    load_revocation_for_token,
    load_revocation_impacts,
    load_revocations,
    load_submission,
    save_chain,
    snapshot_current_keys,
    token_exists,
    upsert_principal,
    upsert_quota,
)
from .engine import (
    KeyStatus,
    affected_token_ids,
    chain_tip_token,
    evaluate_request,
    validate_chain,
)
from .models import (
    CapabilityToken,
    ChainRecord,
    ChainSubmission,
    CoRedeemLegResult,
    CoRedeemRequest,
    CoRedeemResult,
    CoRedemptionEvent,
    ConflictDetail,
    EvaluateRequest,
    EvaluateResult,
    KeyDeactivationEvent,
    KeyDeactivationIn,
    KeyDeactivationResult,
    KeyRotationIn,
    PrincipalIn,
    PrincipalOut,
    PrincipalRotationOut,
    QuotaIn,
    QuotaResult,
    QuotaStatus,
    RedemptionEvent,
    RedeemRequest,
    RedeemResult,
    ReservationEvent,
    ReservationResult,
    ReserveRequest,
    RevocationEvent,
    RevocationImpactsResult,
    RevocationRequest,
    RevocationResult,
    SubmissionResult,
)
from .security import (
    canonical_co_redemption_hash,
    canonical_json,
    canonical_redemption_hash,
    canonical_reservation_hash,
    canonical_revocation_hash,
    canonical_submission_hash,
    sha256_hex,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_conn() as conn:
        init_db(conn)
    yield


app = FastAPI(
    title="委托能力链验证 API",
    description=(
        "客户端提交根授权和以 parent_id 相连的委托令牌；服务验签、检测断链与环，"
        "并强制路径 / 方法 / 时间窗 / IP 网段只能逐级收窄。"
        "支持按时间生效的不可变撤销事件、请求级判定、链末端令牌的一次性访问核销、"
        "双主体会签核销（主授权链与复核链的末端在同一事务内同时核销或都不核销），"
        "撤销事件写入时同事务保存其追溯影响清单（被命中的成功核销，可按撤销 "
        "request_key 查询），按代次管理的签发主体 HMAC 密钥轮换"
        "（既有链按提交时锁定的代次重验），以及疑似失陷签发密钥按主体 + 代次"
        "不可撤销地停用（立即生效，轮换不解除，已提交链在求值 / 核销 / 会签中拒绝），"
        "并可为链末端 subject 设置可调整的跨链成功核销总额度（未设置不限额；"
        "已用量含设置前的成功单链核销与会签参与侧，余额检查在既有授权 / 撤销 / "
        "停用判定全部通过后进行，余额不足不核销、不占键），以及为单链访问提供"
        "短时额度预留（1～300 秒：仅在主体已设额度、授权允许、令牌未核销且可用"
        "额度充足时占一份，到期自动释放；普通核销 / 会签不得占用预留份额与被"
        "预留的令牌，核销可携带预留键把预留份额转为已用）。"
    ),
    version="1.8.0",
    lifespan=lifespan,
)


def _chain_secret_lookup(conn: sqlite3.Connection, chain_id: str):
    """按链提交时锁定的密钥归属构造验签查询。

    - 提交时已注册的主体：固定使用链归属记录中的那一代密钥——轮换不影响
      既有链的验签结论，既有无效链也不会因新密钥恰好匹配而翻转为有效；
    - 提交时未注册的主体（缺失事实已随链持久化）：一律按 unknown_issuer
      处理——事后注册该主体、甚至轮换到匹配旧签名的密钥，都不会让旧链
      在查询 / 重放 / 求值 / 核销中翻转为有效；
    - 归属表与缺失表都无记录（只会出现在尚未回填的极旧数据上）：同样按
      提交时未注册处理，拒绝放行。
    """
    recorded = load_chain_key_generations(conn, chain_id)
    missing = load_chain_missing_issuers(conn, chain_id)

    def lookup(name: str) -> str | None:
        if name in missing:
            return None
        generation = recorded.get(name)
        if generation is None:
            return None
        return get_secret_at_generation(conn, name, generation)

    return lookup


def _chain_key_status_lookup(
    conn: sqlite3.Connection,
    chain_id: str,
    deactivated: dict[tuple[str, int], KeyDeactivationEvent] | None = None,
):
    """按链提交时锁定的密钥归属构造“代次停用状态”查询（供实时求值 / 核销 / 会签）。

    - 提交时已注册的主体：按归属表中的代次查停用表——停用命中（主体, 代次）
      才拒绝；只停用当前代次不影响绑定其他代次的链；
    - 提交时未注册 / 无归属的主体：返回 ``None``，仍按 unknown_issuer 处理，
      停用状态不会让这类链的结论发生任何翻转。

    ``deactivated`` 为调用方在同一事务内一次性读入的停用快照（会签两侧共用
    同一份），保证各签发节点与并发停用交错时对应同一份已提交状态。
    """
    recorded = load_chain_key_generations(conn, chain_id)
    missing = load_chain_missing_issuers(conn, chain_id)
    if deactivated is None:
        deactivated = load_deactivated_keys(conn)

    def lookup(name: str):
        if name in missing:
            return None
        generation = recorded.get(name)
        if generation is None:
            return None
        event = deactivated.get((name, generation))
        if event is not None:
            return KeyStatus(
                generation=generation, deactivated=True, reason=event.reason
            )
        return KeyStatus(generation=generation, deactivated=False)

    return lookup


def _current_key_status_lookup(
    snapshot: dict[str, tuple[str, int]],
    deactivated: dict[tuple[str, int], KeyDeactivationEvent],
):
    """新链提交时的密钥状态查询：按提交瞬间的当前代次快照判定停用。

    验签密钥与代次归属均取自同一份提交时快照；停用状态也以事务内读入的
    快照为准，保证“归属与判定对应一致的已提交状态”。
    """

    def lookup(name: str):
        if name not in snapshot:
            return None
        generation = snapshot[name][1]
        event = deactivated.get((name, generation))
        if event is not None:
            return KeyStatus(
                generation=generation, deactivated=True, reason=event.reason
            )
        return KeyStatus(generation=generation, deactivated=False)

    return lookup


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/principals", response_model=PrincipalOut, status_code=201)
def register_principal(
    payload: PrincipalIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalOut:
    """注册一个签发主体及其 HMAC 密钥（演示 / 运维引导用）。"""
    try:
        created = upsert_principal(conn, payload.name, payload.hmac_secret)
    except sqlite3.IntegrityError:
        created = False
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"主体 {payload.name!r} 已存在",
        )
    return PrincipalOut(name=payload.name)


@app.post("/api/v1/principals/{name}/rotate-key", response_model=PrincipalRotationOut)
def rotate_principal_key(
    name: str, payload: KeyRotationIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalRotationOut:
    """轮换已注册主体的 HMAC 密钥：原子安装新一代密钥并切换为当前代。

    - 轮换后**新提交**的链只按新密钥验签（旧密钥签出的新链得到 ``bad_signature``）；
    - 轮换前已保存的链按提交时锁定的代次继续用原密钥重验，结论不变；
    - 整个切换在同一事务（``BEGIN IMMEDIATE``）内完成：主体不存在（404）、
      新密钥与当前相同（409）或任何写失败都不会留下部分切换；
    - 响应只包含主体名、新代次与轮换时间，不回显密钥。
    """
    conn.execute("BEGIN IMMEDIATE")
    row = get_principal_key_row(conn, name)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"主体 {name!r} 不存在，无法轮换密钥",
        )
    if payload.hmac_secret == row["hmac_secret"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="新密钥与当前密钥相同；轮换未执行",
        )
    generation, rotated_at = install_next_key_generation(
        conn, name, payload.hmac_secret
    )
    return PrincipalRotationOut(name=name, generation=generation, rotated_at=rotated_at)


@app.post(
    "/api/v1/principals/{name}/generations/{generation}/deactivate-key",
    response_model=KeyDeactivationResult,
    status_code=201,
)
def deactivate_principal_key(
    name: str,
    generation: int,
    payload: KeyDeactivationIn,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """疑似失陷时停用某主体的指定代次密钥（立即生效、不可撤销）。

    - 停用按（主体名, 密钥代次）定位：不删除任何密钥材料，已提交链仍按提交时
      锁定的代次取钥，但在后续只读求值、首次单链核销与双链会签中从对应签发
      节点拒绝（轨迹 ``key_active`` 标出 ``key_deactivated`` 及停用原因）；
    - 停用与请求时间无关，轮换也**不解除**旧代次的停用；
    - 同一（主体, 代次）以相同原因重复调用：幂等返回 200、``replayed=true``；
      换原因返回 409（停用不可撤销 / 不可改写）；
    - 主体未注册（404）、代次不存在（404）；代次必须为正整数（422）；
    - 与链提交 / 核销同以 ``BEGIN IMMEDIATE`` 串行化：归属与停用判定对应
      一致的已提交状态。响应不携带任何密钥材料。
    """
    if generation < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="密钥代次必须为正整数（注册为第 1 代）",
        )

    conn.execute("BEGIN IMMEDIATE")

    # 1) 幂等 / 冲突：同一（主体, 代次）只能停用一次，原因随事件冻结
    existing = load_key_deactivation(conn, name, generation)
    if existing is not None:
        if existing.reason == payload.reason:
            result = KeyDeactivationResult(replayed=True, event=existing)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"主体 {name!r} 第 {generation} 代密钥已停用，"
                    "停用不可撤销且停用原因不可改写"
                ),
                "principal": name,
                "generation": generation,
                "existing_reason": existing.reason,
                "received_reason": payload.reason,
            },
        )

    # 2) 主体与代次必须存在（未注册主体 / 越界代次均 404）
    if not key_generation_exists(conn, name, generation):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"主体 {name!r} 不存在第 {generation} 代密钥，无法停用",
        )

    event = KeyDeactivationEvent(
        principal=name,
        generation=generation,
        reason=payload.reason,
        deactivated_at=datetime.now(timezone.utc),
    )
    try:
        insert_key_deactivation(conn, event)
    except sqlite3.IntegrityError:
        # 并发下 (principal, generation) 唯一约束兜底：另一事务已先停用该代次。
        # 同原因按幂等重放返回原事件；原因不同则冲突（停用原因不可改写）。
        raced = load_key_deactivation(conn, name, generation)
        if raced is not None and raced.reason == payload.reason:
            result = KeyDeactivationResult(replayed=True, event=raced)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"主体 {name!r} 第 {generation} 代密钥已被并发请求停用，"
                "且停用原因与本次请求不同（停用原因不可改写）"
            ),
        )

    result = KeyDeactivationResult(replayed=False, event=event)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.get("/api/v1/subjects/{subject}/redemption-quota", response_model=QuotaResult)
def get_redemption_quota(
    subject: str, conn: sqlite3.Connection = Depends(get_db)
) -> QuotaResult:
    """查询链末端 subject 的跨链成功核销总额度口径：额度、已用量、有效预留与可用量。

    - 已用量 ``used`` = 该主体在全部链上的**成功单链核销**数，加上**会签中该主体
      参与的一侧**的次数（每笔会签对每个参与主体计一次）；包含额度设置之前的
      历史成功核销；追溯撤销 / 密钥停用不退还历史用量；
    - 有效预留 ``reserved`` = 该主体当前未过期、未转为核销的短时预留数
      （每笔占一份额度，过期自动释放）；
    - 可用量 ``available`` = ``limit - used - reserved``：普通单链核销、会签与
      新预留实际可用的份额；``remaining`` = ``limit - used`` 为含预留份额的毛剩余；
    - 从未设置（或已清除）额度时 ``limit=null``、``remaining=null``、
      ``available=null``，表示**不限额**（``used`` / ``reserved`` 照常统计返回）；
    - 口径只依赖持久化的额度行、只追加的核销记录与预留行，服务重启后不变。
    """
    status_ = get_quota_status(conn, subject)
    return QuotaResult(
        subject=status_.subject,
        limit=status_.limit,
        used=status_.used,
        reserved=status_.reserved,
        remaining=status_.remaining,
        available=status_.available,
        updated_at=status_.updated_at,
        previous_limit=None,
    )


@app.put("/api/v1/subjects/{subject}/redemption-quota", response_model=QuotaResult)
def put_redemption_quota(
    subject: str,
    payload: QuotaIn,
    conn: sqlite3.Connection = Depends(get_db),
) -> QuotaResult:
    """为链末端 subject 设置 / 调整 / 清除跨链成功核销总额度。

    - 请求体 ``{"limit": N}``：把额度设为非负整数 N；``{"limit": null}`` 清除
      额度、恢复**不限额**（与从未设置等价，但保留设置时间）；
    - 额度可随时调高；**调低（或设为有限值）不得低于当前已用量与有效预留之和**
      （``used + reserved``，调低不能侵占尚未过期 / 未核销的预留份额）——否则
      返回 `409 Conflict`，响应给出当前额度、已用量、有效预留与可用量，本次不改动；
    - 已用量包含设置之前的成功单链核销与会签参与侧，口径重启后不变；
    - 与核销 / 会签 / 预留同以 ``BEGIN IMMEDIATE`` 串行化：并发核销与额度调整
      不会超发（先提交的核销计入已用量，随后的调整只能基于该已用量判定）。
    """
    conn.execute("BEGIN IMMEDIATE")
    now = datetime.now(timezone.utc)
    current = get_quota_status(conn, subject, now)
    if payload.limit is not None and payload.limit < current.used + current.reserved:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"主体 {subject!r} 的核销额度不能低于已用量与有效预留之和："
                    f"请求额度 {payload.limit} < 已用量 {current.used} + "
                    f"有效预留 {current.reserved}；历史成功核销（含额度设置前的"
                    "单链核销与会签参与侧）不可退还，未过期预留到期前不得侵占"
                ),
                "subject": subject,
                "requested_limit": payload.limit,
                "limit": current.limit,
                "used": current.used,
                "reserved": current.reserved,
                "remaining": current.remaining,
                "available": current.available,
            },
        )
    updated_at = datetime.now(timezone.utc)
    previous_limit = upsert_quota(conn, subject, payload.limit, updated_at)
    after = get_quota_status(conn, subject, now)
    return QuotaResult(
        subject=subject,
        limit=after.limit,
        used=after.used,
        reserved=after.reserved,
        remaining=after.remaining,
        available=after.available,
        updated_at=after.updated_at,
        previous_limit=previous_limit,
    )


@app.post(
    "/api/v1/chains",
    response_model=SubmissionResult,
    responses={409: {"model": ConflictDetail}},
    status_code=201,
)
def submit_chain(
    submission: ChainSubmission,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条能力链。

    - 相同 chain_id 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 chain_id 但内容变化：返回 409 冲突；
    - 新 chain_id：持久化并返回 201。完整性失败也会持久化（含失败轨迹）。

    验签严格使用“提交时各签发主体的当前密钥代次”快照，并把该代次归属随链
    持久化：与并发轮换交错时，链的密钥归属与提交时的验签结果始终一致。
    提交时未注册的签发者同样把“缺失密钥”这一事实随链持久化：事后注册该
    主体（或轮换到匹配旧签名的密钥）都不会让这条链的验签结论翻转。
    """
    received_hash = canonical_submission_hash(
        submission.chain_id, submission.tokens
    )

    # 立即取写锁：重放冲突判定、新链“快照 + 验签 + 停用判定 + 归属落库”
    # 全部在同一写事务内，与并发轮换 / 停用 / 核销串行化
    conn.execute("BEGIN IMMEDIATE")
    existing_hash = _existing_hash(conn, submission.chain_id)

    if existing_hash is not None:
        if existing_hash == received_hash:
            # 幂等重放：无条件返回**首次提交时落库的完整性报告**。
            # 同内容重放始终返回原完整性结论——轮换 / 事后注册 / 密钥停用
            # 都不改变重放结果（与链查询返回的提交时报告完全一致）。
            record = load_chain_record(conn, submission.chain_id)
            assert record is not None
            result = SubmissionResult(
                chain_id=submission.chain_id,
                replayed=True,
                integrity=record["integrity"],
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"chain_id={submission.chain_id!r} 已存在但内容不同；"
                    "相同 chain_id 不允许提交不同内容"
                ),
                "chain_id": submission.chain_id,
                "existing_sha256": existing_hash,
                "received_sha256": received_hash,
            },
        )

    # 新链：在已持有的写事务内快照各签发主体的当前密钥 / 代次与密钥停用状态；
    # 验签、停用判定与归属记录使用同一事务内的同一份快照——与并发轮换 / 停用
    # 交错时，归属与判定严格对应提交时的已提交状态。快照之外的签发者
    # （提交时未注册）把“缺失密钥”事实一并随链持久化。
    issuers = {t.issuer for t in submission.tokens}
    snapshot = snapshot_current_keys(conn, issuers)
    deactivated = load_deactivated_keys(conn)
    report, _ = validate_chain(
        submission,
        lambda name: snapshot[name][0] if name in snapshot else None,
        key_status_lookup=_current_key_status_lookup(snapshot, deactivated),
    )
    save_chain(
        conn,
        submission,
        received_hash,
        report,
        {name: generation for name, (_, generation) in snapshot.items()},
        missing_issuers=issuers - snapshot.keys(),
    )
    result = SubmissionResult(
        chain_id=submission.chain_id, replayed=False, integrity=report
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _existing_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


@app.get("/api/v1/chains/{chain_id}", response_model=ChainRecord)
def get_chain(
    chain_id: str, conn: sqlite3.Connection = Depends(get_db)
) -> dict:
    record = load_chain_record(conn, chain_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    return record


@app.post("/api/v1/chains/{chain_id}/evaluate", response_model=EvaluateResult)
def evaluate_chain(
    chain_id: str,
    payload: EvaluateRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> EvaluateResult:
    # 显式开启只读事务：链、撤销事件与停用表在同一快照下读取，
    # 与并发停用 / 提交交错时各节点判定对应同一份已提交状态。
    # 停用与请求时间无关——把 at 指向停用之前的过去时刻仍会被拒绝。
    conn.execute("BEGIN")
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    revocations = load_revocations(conn, chain_id)
    deactivated = load_deactivated_keys(conn)
    return evaluate_request(
        submission,
        payload,
        _chain_secret_lookup(conn, chain_id),
        revocations=revocations,
        key_status_lookup=_chain_key_status_lookup(conn, chain_id, deactivated),
    )


@app.post("/api/v1/chains/{chain_id}/reservations")
def reserve_quota(
    chain_id: str,
    payload: ReserveRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """为一次单链访问预留一份短时额度（有效秒数 1～300，到期自动释放）。

    判定时间以**服务端接收时刻**（UTC）实时重算现有验签 / 权限范围 / 撤销 /
    密钥停用状态；全部工作在同一 SQLite 事务（``BEGIN IMMEDIATE``）内：

    - 201 Created：目标确为链末端、判定允许、主体**已设额度**且可用量
      （``limit - used - reserved``）充足——占一份额度，返回 ``expires_at``；
    - 200 OK：同 ``reservation_key`` 同内容重放（``replayed=true``，返回首次
      结果与首次到期时间）；或预留失败（``reserved=false``，不占用
      ``reservation_key``）：授权 / 撤销 / 停用判定拒绝（``decision="deny"``），
      或判定允许但主体未设额度（``deny_reason="quota_unset"``）或可用量不足
      （``deny_reason="quota_exhausted"``）；
    - 409 Conflict：同 ``reservation_key`` 换内容；目标不是链末端；令牌此前已
      核销；令牌已持有另一键的有效预留（同一令牌只能有一笔有效预留）；
    - 404 Not Found：链不存在，或令牌不属于该链；
    - 422：输入校验失败（如 ``ttl_seconds`` 超出 1～300）。

    过期预留自动释放（不再占额度、不再占用令牌与预留键）；同一令牌在过期后
    可重新预留。预留的份额只能由携带同一预留键、同访问内容的单链核销转为
    已用——普通核销与会签既不得占用被预留的令牌，也不得占用预留的额度份额。
    """
    content_hash = canonical_reservation_hash(
        chain_id,
        payload.token_id,
        payload.reservation_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
        payload.ttl_seconds,
    )

    # 立即取写锁：重放 / 冲突判定、过期释放与新预留“判定 + 占份”串行化
    conn.execute("BEGIN IMMEDIATE")
    now = datetime.now(timezone.utc)

    # 1) reservation_key 幂等 / 冲突（仅未过期的预留占用键；过期即释放）
    existing = load_reservation_by_key(conn, payload.reservation_key)
    if existing is not None:
        event, first_result_json = existing
        if event.expires_at > now:
            if event.content_sha256 != content_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "detail": (
                            f"reservation_key={payload.reservation_key!r} 已用于"
                            "另一笔有效预留，同一 reservation_key 不得更换目标或内容"
                        ),
                        "reservation_key": payload.reservation_key,
                        "existing_sha256": event.content_sha256,
                        "received_sha256": content_hash,
                    },
                )
            # 同键同内容且未过期：回放首次预留结果（到期时间与首次一致）
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=json.loads(first_result_json) | {"replayed": True},
            )
        # 已过期：自动释放（同键重试按一笔全新预留重新判定）
        delete_reservation(conn, payload.reservation_key)

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标必须确为链末端（与核销一致：预留针对的就是将来的单链核销）
    tip = chain_tip_token(submission)
    if tip is None or tip.token_id != payload.token_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 不是链 {chain_id!r} 的末端令牌，"
                    "额度预留只允许对链末端执行"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "chain_tip_token_id": None if tip is None else tip.token_id,
            },
        )

    # 5) 已核销令牌不得再预留（核销后令牌只能核销一次，预留无意义）
    prior = load_redemption_for_token(conn, chain_id, payload.token_id)
    if prior is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，已核销令牌不能再预留额度"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
                "redeemed_at": prior.redeemed_at.isoformat(),
            },
        )

    # 6) 同一令牌只能有一笔有效预留（过期预留自动释放后可重新预留）
    token_reservation = load_reservation_for_token(conn, chain_id, payload.token_id)
    if token_reservation is not None:
        if token_reservation.expires_at > now:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"token_id={payload.token_id!r} 已持有有效预留 "
                        f"（reservation_key={token_reservation.reservation_key!r}），"
                        "同一令牌只能有一笔有效预留"
                    ),
                    "chain_id": chain_id,
                    "token_id": payload.token_id,
                    "existing_reservation_key": token_reservation.reservation_key,
                    "expires_at": token_reservation.expires_at.isoformat(),
                },
            )
        # 已过期：惰性释放，允许本请求重新预留
        delete_reservation(conn, token_reservation.reservation_key)

    # 7) 以接收时刻重算现有验签 / 收窄 / 撤销 / 密钥停用 / 请求级权限
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decision = evaluate_request(
        submission,
        evaluation,
        _chain_secret_lookup(conn, chain_id),
        revocations=load_revocations(conn, chain_id),
        key_status_lookup=_chain_key_status_lookup(
            conn, chain_id, load_deactivated_keys(conn)
        ),
    )

    if decision.decision != "allow":
        # 判定拒绝：不预留、不占用 reservation_key（与核销一致，后续可重试）
        result = ReservationResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            reservation_key=payload.reservation_key,
            reserved=False,
            replayed=False,
            evaluated_at=now,
            expires_at=None,
            decision=decision.decision,
            first_failed_node=decision.first_failed_node,
            first_failed_reason=decision.first_failed_reason,
            body_sha256=decision.body_sha256,
            first_revoked_node=decision.first_revoked_node,
            trace=decision.trace,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 8) 既有判定全部通过后，才检查链末端 subject 的额度：
    #    预留要求主体已设额度，且可用量（limit - used - reserved）充足。
    tip_subject = tip.subject
    quota = get_quota_status(conn, tip_subject, now)
    if quota.limit is None:
        result = ReservationResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            reservation_key=payload.reservation_key,
            reserved=False,
            replayed=False,
            evaluated_at=now,
            expires_at=None,
            decision="allow",
            first_failed_node=None,
            first_failed_reason=None,
            body_sha256=decision.body_sha256,
            first_revoked_node=None,
            trace=decision.trace,
            deny_reason="quota_unset",
            quota=quota,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )
    if quota.available is not None and quota.available <= 0:
        result = ReservationResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            reservation_key=payload.reservation_key,
            reserved=False,
            replayed=False,
            evaluated_at=now,
            expires_at=None,
            decision="allow",
            first_failed_node=None,
            first_failed_reason=None,
            body_sha256=decision.body_sha256,
            first_revoked_node=None,
            trace=decision.trace,
            deny_reason="quota_exhausted",
            quota=quota,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 9) 全部条件满足：占一份额度，落库预留（到期时间 = 接收时刻 + 有效秒数）
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    event = ReservationEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        reservation_key=payload.reservation_key,
        subject=tip_subject,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        created_at=now,
        expires_at=expires_at,
    )
    result = ReservationResult(
        chain_id=chain_id,
        token_id=payload.token_id,
        reservation_key=payload.reservation_key,
        reserved=True,
        replayed=False,
        evaluated_at=now,
        expires_at=expires_at,
        decision="allow",
        first_failed_node=None,
        first_failed_reason=None,
        body_sha256=decision.body_sha256,
        first_revoked_node=None,
        trace=decision.trace,
        deny_reason=None,
        quota=None,
    )
    try:
        insert_reservation(conn, event, "__quota_result_placeholder__")
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（reservation_key 或 chain_id+token_id 抢占）
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": f"预留请求与已有记录冲突: {exc}"},
        )

    # 预留已落库：补算占用一份后的额度口径并回填首次响应（重放即回放这份结果）
    result.quota = get_quota_status(conn, tip_subject, now)
    conn.execute(
        "UPDATE reservations SET result_json = ? WHERE reservation_key = ?",
        (
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False),
            payload.reservation_key,
        ),
    )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.post("/api/v1/chains/{chain_id}/redeem")
def redeem_chain(
    chain_id: str,
    payload: RedeemRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """对链末端令牌执行一次性访问核销。

    判定时间不由调用方提供，而以**服务端接收时刻**（UTC）实时重算现有
    验签 / 权限范围 / 撤销状态；全部工作在同一 SQLite 事务（``BEGIN IMMEDIATE``）内：

    - 201 Created：目标确为链末端且判定允许、可用额度充足（或使用了匹配的
      有效预留份额）——记录核销（该令牌此后不可再核销）；
    - 200 OK：同 ``request_key`` 同内容重放，返回**首次结果**（``replayed=true``，
      即使令牌随后过期 / 被撤销）；或目标为末端但本次判定拒绝（``redeemed=false``，
      不核销、不占用 request_key，后续有效请求仍可尝试），包括既有授权 / 撤销 /
      停用检查通过但链末端 subject 的可用额度（``limit - used - reserved``）
      已用尽（``deny_reason="quota_exhausted"``，响应给出额度口径，调高额度
      后同一把键仍可成功），以及预留相关拒绝（见下）；
    - 409 Conflict：同 ``request_key`` 换内容；目标不是链末端；令牌此前已被核销
      （并发请求仅一笔成功，其余统一报告已核销，与其当下是否过期 / 被撤销无关）；
    - 404 Not Found：链不存在，或令牌不属于该链；
    - 422：输入校验失败（如非法 source_ip / HTTP 方法）。

    额度按链末端 subject 跨链累计（成功单链核销 + 会签中该主体参与的一侧，
    每次算一次，含设置前的历史用量）；余额检查在既有授权判定 / 撤销 / 密钥
    停用检查全部通过后才进行——这些检查拒绝时不查余额，响应也不带额度口径。

    **短时额度预留**：请求体可携带 ``reservation_key`` 使用事先预留的份额——
    仅当该令牌持有同键、同访问内容（路径 / 方法 / 来源 IP / 请求体）且未过期
    的有效预留时才核销，并在同一事务内把预留转为已用（预留行删除、已用量 +1，
    可用量不变；此时不再重复检查余额，但仍重新检查验签 / 撤销 / 密钥停用 /
    权限）。预留键不存在 / 已过期 / 内容不符（``deny_reason="reservation_mismatch"``）
    或授权重新判定拒绝时，不核销、不占用 request_key、不计已用（预留仍保留至
    到期）。不带预留键的普通核销**不得占用被预留的令牌**
    （``deny_reason="token_reserved"``），其可用额度也不含他人预留的份额。
    """
    content_hash = canonical_redemption_hash(
        chain_id,
        payload.token_id,
        payload.request_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
        payload.reservation_key,
    )

    # 立即取写锁，串行化“判定 + 插入”，保证并发请求仅一笔成功核销
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（成功核销才会占用 request_key）
    existing = load_redemption_by_request_key(conn, payload.request_key)
    if existing is not None:
        event, first_result_json = existing
        if event.content_sha256 != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"request_key={payload.request_key!r} 已用于另一次核销，"
                        "同一 request_key 不得更换目标或请求内容"
                    ),
                    "request_key": payload.request_key,
                    "existing_sha256": event.content_sha256,
                    "received_sha256": content_hash,
                },
            )
        # 同键同内容：无条件回放首次结果（令牌随后过期 / 被撤销也不变）
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json.loads(first_result_json) | {"replayed": True},
        )

    # request_key 与会签核销共用同一键空间：已被成功会签占用的键不得复用
    co_existing = load_co_redemption_by_request_key(conn, payload.request_key)
    if co_existing is not None:
        co_event, _ = co_existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于一次双主体会签，"
                    "同一 request_key 不得复用"
                ),
                "request_key": payload.request_key,
                "existing_sha256": co_event.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标必须确为链末端（结构选路：唯一根 → 唯一子链的最后一个令牌）
    tip = chain_tip_token(submission)
    if tip is None or tip.token_id != payload.token_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 不是链 {chain_id!r} 的末端令牌，"
                    "一次性核销只允许对链末端执行"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "chain_tip_token_id": None if tip is None else tip.token_id,
            },
        )

    # 5) 同一令牌只能成功核销一次：已核销则明确报告（并发输家亦走此路）
    prior = load_redemption_for_token(conn, chain_id, payload.token_id)
    if prior is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
                "redeemed_at": prior.redeemed_at.isoformat(),
            },
        )

    # 5.5) 短时额度预留解析（在授权判定之前；拒绝不核销、不占 request_key、不计已用）：
    #      - 携带 reservation_key：该令牌必须持有同键、同访问内容且未过期的有效
    #        预留，核销成功时在同一事务内把该预留转为已用；
    #      - 未携带：普通核销不得占用被他人预留的令牌。
    now = datetime.now(timezone.utc)
    reservation_to_consume = None
    active_reservation = load_reservation_for_token(conn, chain_id, payload.token_id)
    if active_reservation is not None and active_reservation.expires_at <= now:
        # 过期自动释放：不再占用令牌与额度份额
        delete_reservation(conn, active_reservation.reservation_key)
        active_reservation = None
    if payload.reservation_key is not None:
        if active_reservation is None or not _reservation_matches(
            active_reservation, payload
        ):
            result = RedeemResult(
                chain_id=chain_id,
                token_id=payload.token_id,
                request_key=payload.request_key,
                redeemed=False,
                replayed=False,
                evaluated_at=now,
                redeemed_at=None,
                decision="deny",
                first_failed_node=None,
                first_failed_reason=None,
                body_sha256=_body_fingerprint(payload.body),
                first_revoked_node=None,
                trace=[],
                deny_reason="reservation_mismatch",
                quota=None,
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        reservation_to_consume = active_reservation
    elif active_reservation is not None:
        result = RedeemResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            decision="deny",
            first_failed_node=None,
            first_failed_reason=None,
            body_sha256=_body_fingerprint(payload.body),
            first_revoked_node=None,
            trace=[],
            deny_reason="token_reserved",
            quota=None,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 6) 以接收时刻重算现有验签 / 收窄 / 撤销 / 请求级权限
    #    （验签按链提交时锁定的密钥代次取钥，轮换不改变既有链结论；
    #    携带预留键时同样重新检查验签 / 撤销 / 密钥停用 / 权限）
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decision = evaluate_request(
        submission,
        evaluation,
        _chain_secret_lookup(conn, chain_id),
        revocations=load_revocations(conn, chain_id),
        key_status_lookup=_chain_key_status_lookup(
            conn, chain_id, load_deactivated_keys(conn)
        ),
    )

    if decision.decision != "allow":
        # 判定拒绝：既不核销，也不占用 request_key；
        # 按约定只有可成功核销时才检查余额，授权 / 撤销 / 停用拒绝不做余额判定。
        result = RedeemResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            decision=decision.decision,
            first_failed_node=decision.first_failed_node,
            first_failed_reason=decision.first_failed_reason,
            body_sha256=decision.body_sha256,
            first_revoked_node=decision.first_revoked_node,
            trace=decision.trace,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 7) 既有授权判定 / 撤销 / 密钥停用检查全部通过后，才检查链末端 subject
    #    的跨链成功核销总额度（未设置额度 = 不限额）。
    #    已用量含设置前的成功单链核销与会签参与侧；可用量不足明确拒绝：
    #    不核销、不占用 request_key，调高额度后同一把键仍可成功。
    #    使用匹配预留份额的核销不再重复检查余额——预留时已占一份，本次只是
    #    把该份额从“预留”转为“已用”（可用量不变）。
    tip_subject = tip.subject
    quota = get_quota_status(conn, tip_subject, now)
    if (
        reservation_to_consume is None
        and quota.limit is not None
        and quota.available is not None
        and quota.available <= 0
    ):
        result = RedeemResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            decision="allow",
            first_failed_node=None,
            first_failed_reason=None,
            body_sha256=decision.body_sha256,
            first_revoked_node=None,
            trace=decision.trace,
            deny_reason="quota_exhausted",
            quota=quota,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    event = RedemptionEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        evaluated_at=now,
        redeemed_at=now,
        created_at=now,
    )
    # 未设置额度（不限额）时结果不带 quota，直接落库最终响应；
    # 设置了额度时先落占位响应、核销后补算扣减口径再回填（见下）。
    result = RedeemResult(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        redeemed=True,
        replayed=False,
        evaluated_at=now,
        redeemed_at=now,
        decision=decision.decision,
        first_failed_node=decision.first_failed_node,
        first_failed_reason=decision.first_failed_reason,
        body_sha256=decision.body_sha256,
        first_revoked_node=decision.first_revoked_node,
        trace=decision.trace,
        deny_reason=None,
        quota=None if quota.limit is None else QuotaStatus(
            subject=tip_subject, limit=quota.limit,
            used=quota.used, reserved=quota.reserved,
            remaining=quota.remaining, available=quota.available,
            updated_at=quota.updated_at,
        ),
    )
    initial_result_json = (
        "__quota_result_placeholder__"
        if quota.limit is not None
        else json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    )
    try:
        insert_redemption(conn, event, initial_result_json)
        # 使用预留份额的核销：同一事务内把预留转为已用（删除预留行，
        # 已用量随核销记录 +1，预留数 -1，可用量不变）
        if reservation_to_consume is not None:
            delete_reservation(conn, reservation_to_consume.reservation_key)
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）
        prior = load_redemption_for_token(conn, chain_id, payload.token_id)
        detail = (
            {
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
            }
            if prior is not None
            else {"detail": f"核销请求与已有记录冲突: {exc}"}
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=detail
        )

    # 核销已落库：补算扣减后的额度口径并回填首次响应（重放即回放这份结果，
    # 与首次口径一致、不重复计数）。未设置额度时首次响应已直接落库，无需回填。
    if quota.limit is not None:
        result.quota = get_quota_status(conn, tip_subject, now)
        conn.execute(
            "UPDATE redemptions SET result_json = ? WHERE request_key = ?",
            (
                json.dumps(result.model_dump(mode="json"), ensure_ascii=False),
                payload.request_key,
            ),
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _body_fingerprint(body: object) -> str:
    """请求体 SHA-256 指纹（与判定轨迹同一口径；预留层拒绝时无轨迹可附）。"""
    return sha256_hex(canonical_json(body).encode("utf-8"))


def _reservation_matches(
    reservation: "ReservationEvent", payload: RedeemRequest
) -> bool:
    """核销请求是否与预留匹配：同预留键，且访问内容（路径 / 方法 / 来源 IP /
    请求体）逐项一致（链与令牌由查询条件保证；过期判定由调用方完成）。"""
    return (
        reservation.reservation_key == payload.reservation_key
        and reservation.request_path == payload.request_path
        and reservation.method == payload.method
        and reservation.source_ip == payload.source_ip
        and canonical_json(reservation.request_body) == canonical_json(payload.body)
    )


@app.post("/api/v1/co-redemptions")
def co_redeem(
    payload: CoRedeemRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """双主体会签：一次访问需主授权链与复核链的末端同时允许，才一并核销。

    整个流程在**同一 SQLite 写事务**（``BEGIN IMMEDIATE``）内、以**同一服务端
    接收时刻**（UTC）完成：两条链分别按各自提交时锁定的密钥归属验签，并检查
    撤销、请求级权限与已核销状态。

    - 201 Created：两条链的末端都判定允许、两侧可用额度（不含预留份额）均有
      余量、两侧令牌均无有效预留且均未核销——同一事务内同时记入两侧核销
      （共同核销时间），返回两份判定轨迹与扣减后的额度口径；
    - 200 OK：同 ``request_key`` 同内容重放，返回**首次会签结果**
      （``replayed=true``，即使令牌随后过期 / 被撤销）；或任一侧判定拒绝
      （``redeemed=false``——两侧都不核销、不占用 request_key），包括两侧既有
      检查均通过但任一主体可用额度已用尽（该侧 ``deny_reason="quota_exhausted"``）
      或任一侧令牌持有有效预留（该侧 ``deny_reason="token_reserved"``——
      会签不得占用被预留的令牌与预留份额），两侧均不核销、不占键；
    - 409 Conflict：同 ``request_key`` 换内容（含主 / 复核互换）；两链末端
      subject 相同；目标不是链末端；任一侧此前已被核销（单链核销或会签，
      另一侧不被消耗）；request_key 已被单链核销占用；
    - 404 Not Found：任一链不存在，或令牌不属于对应链；
    - 422：输入校验失败（如两链 chain_id 相同、非法 source_ip / HTTP 方法）。
    """
    content_hash = canonical_co_redemption_hash(
        payload.primary.chain_id,
        payload.primary.token_id,
        payload.review.chain_id,
        payload.review.token_id,
        payload.request_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
    )

    # 立即取写锁：两侧“判定 + 核销”在同一事务内串行化，要么同时落库要么都不落
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（成功会签才占用 request_key）
    existing = load_co_redemption_by_request_key(conn, payload.request_key)
    if existing is not None:
        event, first_result_json = existing
        if event.content_sha256 != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"request_key={payload.request_key!r} 已用于另一次会签，"
                        "同一 request_key 不得更换链、目标或请求内容"
                    ),
                    "request_key": payload.request_key,
                    "existing_sha256": event.content_sha256,
                    "received_sha256": content_hash,
                },
            )
        # 同键同内容：无条件回放首次会签结果（令牌随后过期 / 被撤销也不变）
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json.loads(first_result_json) | {"replayed": True},
        )

    # request_key 与单链核销共用同一键空间：已被单链核销占用的键不得复用
    single_existing = load_redemption_by_request_key(conn, payload.request_key)
    if single_existing is not None:
        single_event, _ = single_existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于一次单链核销，"
                    "同一 request_key 不得复用"
                ),
                "request_key": payload.request_key,
                "existing_sha256": single_event.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 两条链都必须存在、令牌都属于对应链、且都确为各自链的末端
    sides: dict[str, tuple[str, str, ChainSubmission, CapabilityToken]] = {}
    for side_name, side in (("primary", payload.primary), ("review", payload.review)):
        submission = load_submission(conn, side.chain_id)
        if submission is None:
            raise HTTPException(
                status_code=404, detail=f"chain_id {side.chain_id!r} 不存在"
            )
        if not token_exists(conn, side.chain_id, side.token_id):
            raise HTTPException(
                status_code=404,
                detail=(
                    f"chain_id {side.chain_id!r} 中不存在 "
                    f"token_id={side.token_id!r}"
                ),
            )
        tip = chain_tip_token(submission)
        if tip is None or tip.token_id != side.token_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"token_id={side.token_id!r} 不是链 {side.chain_id!r} "
                        "的末端令牌，会签只允许对两侧各自的链末端执行"
                    ),
                    "side": side_name,
                    "chain_id": side.chain_id,
                    "token_id": side.token_id,
                    "chain_tip_token_id": None if tip is None else tip.token_id,
                },
            )
        sides[side_name] = (side.chain_id, side.token_id, submission, tip)

    # 3) 双主体：两链末端令牌的 subject 必须不同
    primary_tip = sides["primary"][3]
    review_tip = sides["review"][3]
    if primary_tip.subject == review_tip.subject:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"两条链末端令牌的 subject 相同（{primary_tip.subject!r}），"
                    "会签要求主授权与复核为不同主体"
                ),
                "subject": primary_tip.subject,
                "primary_chain_id": payload.primary.chain_id,
                "review_chain_id": payload.review.chain_id,
            },
        )

    # 4) 任一侧已核销（单链核销或会签）-> 409，另一侧不被消耗
    for side_name in ("primary", "review"):
        chain_id, token_id, _, _ = sides[side_name]
        prior = load_redemption_for_token(conn, chain_id, token_id)
        if prior is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"token_id={token_id!r} 已在 request_key="
                        f"{prior.request_key!r} 中核销，令牌只能成功核销一次；"
                        "本次会签未消耗任何一侧"
                    ),
                    "side": side_name,
                    "chain_id": chain_id,
                    "token_id": token_id,
                    "existing_request_key": prior.request_key,
                    "redeemed_at": prior.redeemed_at.isoformat(),
                },
            )

    # 5) 以同一接收时刻重算两链的验签 / 收窄 / 撤销 / 请求级权限
    #    （各链分别按其提交时锁定的密钥代次取钥，轮换不改变既有链结论）
    now = datetime.now(timezone.utc)
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decisions = {}
    deactivated = load_deactivated_keys(conn)  # 两侧共用同一停用快照
    for side_name in ("primary", "review"):
        chain_id, _, submission, _ = sides[side_name]
        decisions[side_name] = evaluate_request(
            submission,
            evaluation,
            _chain_secret_lookup(conn, chain_id),
            revocations=load_revocations(conn, chain_id),
            key_status_lookup=_chain_key_status_lookup(conn, chain_id, deactivated),
        )

    # 余额与预留检查只在两侧既有判定都允许时进行：先取两侧末端 subject 的额度
    # 口径（可用量 = limit - used - reserved，不含他人预留的份额），并检查两侧
    # 末端令牌是否持有有效预留（会签不得占用被预留的令牌）；任一侧不可用即
    # 两侧均不核销、不占 request_key。
    quota_by_side: dict[str, QuotaStatus | None] = {"primary": None, "review": None}
    quota_denied_sides: list[str] = []
    token_reserved_sides: list[str] = []
    if all(decisions[s].decision == "allow" for s in ("primary", "review")):
        for side_name in ("primary", "review"):
            side_chain_id, side_token_id, _, side_tip = sides[side_name]
            reservation = load_reservation_for_token(
                conn, side_chain_id, side_token_id
            )
            if reservation is not None and reservation.expires_at > now:
                token_reserved_sides.append(side_name)
            status_ = get_quota_status(conn, side_tip.subject, now)
            # 未设置额度（不限额）：leg.quota 保持 None
            if status_.limit is not None:
                quota_by_side[side_name] = status_
                if status_.available is not None and status_.available <= 0:
                    quota_denied_sides.append(side_name)

    def _leg(side_name: str) -> CoRedeemLegResult:
        reserved = side_name in token_reserved_sides
        exhausted = side_name in quota_denied_sides
        return CoRedeemLegResult(
            chain_id=sides[side_name][0],
            token_id=sides[side_name][1],
            subject=sides[side_name][3].subject,
            decision="deny" if (reserved or exhausted) else decisions[side_name].decision,
            first_failed_node=decisions[side_name].first_failed_node,
            first_failed_reason=decisions[side_name].first_failed_reason,
            first_revoked_node=decisions[side_name].first_revoked_node,
            trace=decisions[side_name].trace,
            deny_reason=(
                "token_reserved" if reserved
                else "quota_exhausted" if exhausted
                else None
            ),
            quota=quota_by_side[side_name],
        )

    legs = {side_name: _leg(side_name) for side_name in ("primary", "review")}
    body_sha256 = decisions["primary"].body_sha256

    if any(leg.decision != "allow" for leg in legs.values()):
        # 任一侧拒绝（既有授权 / 撤销 / 停用，两侧均通过后的可用量不足，
        # 或任一侧令牌持有有效预留）：两侧都不核销，也不占用 request_key。
        result = CoRedeemResult(
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            body_sha256=body_sha256,
            primary=legs["primary"],
            review=legs["review"],
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 6) 两侧都允许、额度均有余量且均未核销：同一事务内同时记入两侧核销
    #    （共同核销时间），随后回填两侧扣减后的额度口径。
    event = CoRedemptionEvent(
        request_key=payload.request_key,
        primary_chain_id=payload.primary.chain_id,
        primary_token_id=payload.primary.token_id,
        review_chain_id=payload.review.chain_id,
        review_token_id=payload.review.token_id,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        evaluated_at=now,
        redeemed_at=now,
        created_at=now,
    )
    result = CoRedeemResult(
        request_key=payload.request_key,
        redeemed=True,
        replayed=False,
        evaluated_at=now,
        redeemed_at=now,
        body_sha256=body_sha256,
        primary=legs["primary"],
        review=legs["review"],
    )
    quota_configured = any(q is not None for q in quota_by_side.values())
    try:
        insert_co_redemption(
            conn,
            event,
            "__quota_result_placeholder__"
            if quota_configured
            else json.dumps(result.model_dump(mode="json"), ensure_ascii=False),
        )
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或任一侧 chain_id+token_id 抢占）
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": f"会签请求与已有记录冲突: {exc}"},
        )

    # 两侧核销均已落库：对设置了额度的主体补算扣减后的口径（每侧 +1），
    # 回填单侧结果后更新首次响应（同键重放回放这份口径、不重复计数）。
    if quota_configured:
        for side_name in ("primary", "review"):
            if quota_by_side[side_name] is not None:
                legs[side_name].quota = get_quota_status(
                    conn, sides[side_name][3].subject, now
                )
        result.primary = legs["primary"]
        result.review = legs["review"]
        conn.execute(
            "UPDATE co_redemptions SET result_json = ? WHERE request_key = ?",
            (
                json.dumps(result.model_dump(mode="json"), ensure_ascii=False),
                payload.request_key,
            ),
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.post(
    "/api/v1/chains/{chain_id}/revocations",
    response_model=RevocationResult,
    status_code=201,
)
def submit_revocation(
    chain_id: str,
    payload: RevocationRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条按时间生效的不可变撤销事件。

    - 相同 ``request_key`` 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 ``request_key`` 但目标 / 内容变化：返回 409 冲突；
    - 链或令牌不存在：404；目标令牌已有撤销事件（含不同 request_key）：409。

    “确认令牌存在”、“追加撤销事件”与“保存该事件的影响清单”在同一 SQLite
    事务（``BEGIN IMMEDIATE``）内完成：事件写入时找出核销时间不早于
    ``effective_at``、早于事件写入时间，且末端令牌为撤销目标或其后代的
    成功核销（单链核销与双链会签均纳入），随事件一并落库；撤销失败时
    整个事务回滚，不会留下影响清单。
    """
    content_hash = canonical_revocation_hash(
        chain_id,
        payload.token_id,
        payload.effective_at,
        payload.reason,
        payload.request_key,
    )

    # 立即取写锁：影响清单的查找与事件写入同事务，并与并发核销
    # （同样 BEGIN IMMEDIATE）串行化——清单恰好覆盖写入前已完成的访问
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（全局唯一键）
    existing_key = load_revocation_by_request_key(conn, payload.request_key)
    if existing_key is not None:
        if existing_key.content_sha256 == content_hash:
            result = RevocationResult(
                replayed=True,
                event=existing_key,
                affected_token_ids=_affected_ids(conn, chain_id, existing_key),
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于另一条撤销事件，"
                    "同一 request_key 不得更换目标或内容"
                ),
                "request_key": payload.request_key,
                "existing_sha256": existing_key.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链（与后续插入在同一事务）
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标令牌不得重复撤销（已撤销令牌不得再次生效为新事件）
    existing_revocation = load_revocation_for_token(
        conn, chain_id, payload.token_id
    )
    if existing_revocation is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{existing_revocation.request_key!r} 中被撤销，"
                    "撤销事件不可变且不可重复"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": existing_revocation.request_key,
            },
        )

    event = RevocationEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        effective_at=payload.effective_at.astimezone(timezone.utc),
        reason=payload.reason,
        request_key=payload.request_key,
        content_sha256=content_hash,
        created_at=datetime.now(timezone.utc),
    )
    # 事件写入时算出影响清单：核销时间不早于 effective_at、早于事件写入时间，
    # 且末端令牌为撤销目标或其后代的成功核销（单链核销与会签均纳入）
    affected_ids = _affected_ids(conn, chain_id, event)
    impacts = compute_revocation_impacts(conn, event, affected_ids)
    try:
        insert_revocation(conn, event)
        insert_revocation_impacts(conn, event, impacts)
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）；
        # 失败整体回滚：事件与影响清单都不会留下
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"撤销事件与已有记录冲突: {exc}",
        )

    result = RevocationResult(
        replayed=False,
        event=event,
        affected_token_ids=affected_ids,
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.get(
    "/api/v1/revocations/{request_key}/impacts",
    response_model=RevocationImpactsResult,
)
def get_revocation_impacts(
    request_key: str, conn: sqlite3.Connection = Depends(get_db)
) -> RevocationImpactsResult:
    """按撤销 ``request_key`` 查询该事件写入时保存的影响清单。

    清单在事件写入的同一事务内计算并随事件保存，之后不可变：核销时间不早于
    ``effective_at``、早于事件写入时间，且末端令牌为撤销目标或其后代的成功
    核销（单链核销与双链会签均纳入；一笔会签只列一次，注明受影响的链与
    主授权 / 复核侧）。无命中返回空清单；撤销事件不存在返回 404。
    """
    event = load_revocation_by_request_key(conn, request_key)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"撤销事件 request_key={request_key!r} 不存在",
        )
    return RevocationImpactsResult(
        request_key=event.request_key,
        chain_id=event.chain_id,
        token_id=event.token_id,
        effective_at=event.effective_at,
        impacts=load_revocation_impacts(conn, request_key),
    )


def _affected_ids(
    conn: sqlite3.Connection, chain_id: str, event: RevocationEvent
) -> list[str]:
    """按存储的完整性轨迹顺序计算受影响令牌（目标及其后代）。"""
    record = load_chain_record(conn, chain_id)
    if record is None:  # 理论不可达：调用前已确认链存在
        return [event.token_id]
    submission = ChainSubmission(
        chain_id=chain_id, tokens=record["tokens"]
    )
    trace_order = [t.token_id for t in record["integrity"].trace]
    return affected_token_ids(submission, trace_order, event)
