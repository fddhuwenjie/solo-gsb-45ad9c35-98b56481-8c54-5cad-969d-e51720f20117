"""请求 / 响应的 Pydantic 模型。"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# 失败原因码（同时用于轨迹节点的 reason 与文档说明）
REASONS = {
    "duplicate_id",
    "missing_root",
    "multiple_roots",
    "broken_link",
    "cycle",
    "disconnected",
    "branch",
    "unknown_issuer",
    "bad_signature",
    "issuer_mismatch",
    "path_widens",
    "method_widens",
    "time_window_widens",
    "ip_widens",
    "before_not_before",
    "after_not_after",
    "method_not_allowed",
    "path_not_covered",
    "ip_not_allowed",
    "revoked",
    "key_deactivated",
    "quota_exhausted",
}

_IPNetwork = IPv4Network | IPv6Network
_PATH_RE = re.compile(r"^/[^\s]*$")
_METHOD_RE = re.compile(r"^[A-Za-z]+$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _ensure_aware(dt: datetime, field: str) -> datetime:
    if dt.tzinfo is None:
        raise ValueError(f"{field} 必须携带时区信息（推荐 UTC，例如 2026-01-01T00:00:00Z）")
    return dt.astimezone(timezone.utc)


class CapabilityToken(BaseModel):
    """委托能力令牌。

    根授权 ``parent_id`` 为 ``None``；其余令牌通过 ``parent_id`` 指向父令牌。
    """

    token_id: str = Field(min_length=1, description="令牌唯一标识")
    parent_id: str | None = Field(default=None, description="父令牌 id；根授权为 null")
    chain_id: str = Field(min_length=1, description="所属能力链 id")
    issuer: str = Field(min_length=1, description="签发者主体名")
    subject: str = Field(min_length=1, description="被授权主体名")
    path_pattern: str = Field(description="资源路径 glob，必须以 / 开头，支持 * 与 **")
    methods: list[str] = Field(min_length=1, description="允许的 HTTP 方法集合")
    not_before: datetime = Field(description="生效时间（含时区）")
    not_after: datetime = Field(description="失效时间（含时区）")
    allow_ip: str | None = Field(default=None, description="可选 CIDR，例如 10.0.0.0/8")
    signature: str = Field(description="HMAC-SHA256 十六进制签名（64 位 hex）")

    @field_validator("path_pattern")
    @classmethod
    def _validate_path(cls, v: str) -> str:
        if not _PATH_RE.match(v):
            raise ValueError("path_pattern 必须以 / 开头且不能包含空白字符")
        return v

    @field_validator("methods")
    @classmethod
    def _validate_methods(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for m in values:
            if not _METHOD_RE.match(m):
                raise ValueError(f"非法 HTTP 方法: {m!r}")
            upper = m.upper()
            if upper not in normalized:
                normalized.append(upper)
        return normalized

    @field_validator("allow_ip")
    @classmethod
    def _validate_cidr(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # 解析校验（IPvAnyNetwork 的宽松形式：主机位非零时按主机处理，这里要求规范网络地址）
        from ipaddress import ip_network

        try:
            net = ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"allow_ip 不是合法的 CIDR 网络: {exc}") from exc
        return str(net)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        if not _HEX64_RE.match(v):
            raise ValueError("signature 必须是 64 位十六进制字符串（HMAC-SHA256）")
        return v.lower()

    @field_validator("not_before", "not_after")
    @classmethod
    def _validate_dt(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "时间字段")

    @model_validator(mode="after")
    def _validate_window(self) -> "CapabilityToken":
        if self.not_after <= self.not_before:
            raise ValueError("not_after 必须晚于 not_before")
        segs = [s for s in self.path_pattern.split("/")[1:] if s != ""]
        for i, seg in enumerate(segs):
            if "**" in seg and seg != "**":
                raise ValueError("** 必须独占整个路径段（例如 /files/**）")
            if seg == "**" and i != len(segs) - 1:
                raise ValueError("** 只能作为 path_pattern 的末段")
        return self


class ChainSubmission(BaseModel):
    """客户端提交的一条完整能力链（根授权 + 若干委托令牌）。"""

    chain_id: str = Field(min_length=1)
    tokens: list[CapabilityToken] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_chain_id(self) -> "ChainSubmission":
        for t in self.tokens:
            if t.chain_id != self.chain_id:
                raise ValueError(f"令牌 {t.token_id} 的 chain_id 与提交不一致")
        return self


class RequestContext(BaseModel):
    """请求级判定 / 核销共用的请求上下文（路径、方法、来源 IP、请求体）。"""

    request_path: str = Field(description="被访问的资源路径")
    method: str = Field(description="HTTP 方法")
    source_ip: str | None = Field(
        default=None, description="请求来源 IP；链上存在 allow_ip 时必填"
    )
    body: Any = Field(
        default=None, description="请求主体，仅记录 SHA-256 指纹用于审计轨迹"
    )

    @field_validator("request_path")
    @classmethod
    def _validate_request_path(cls, v: str) -> str:
        if not _PATH_RE.match(v):
            raise ValueError("request_path 必须以 / 开头且不能包含空白字符")
        return v

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if not _METHOD_RE.match(v):
            raise ValueError(f"非法 HTTP 方法: {v!r}")
        return v.upper()

    @field_validator("source_ip")
    @classmethod
    def _validate_source_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        from ipaddress import ip_address

        try:
            return str(ip_address(v))
        except ValueError as exc:
            raise ValueError(f"source_ip 不是合法 IP: {exc}") from exc


class EvaluateRequest(RequestContext):
    """对已存能力链进行一次实际请求级判定。"""

    at: datetime = Field(description="请求时间（含时区）")

    @field_validator("at")
    @classmethod
    def _validate_at(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "at")


class RedeemRequest(RequestContext):
    """一次性访问核销请求；判定时间由服务端以接收时刻重算（请求体不提供时间）。

    可携带 ``reservation_key`` 使用事先预留的额度份额：仅当该令牌持有同键、
    同访问内容且未过期的有效预留时才核销（预留在同一事务内转为已用）；
    不带预留键的普通核销不得占用被预留的令牌与预留份额。
    """

    token_id: str = Field(min_length=1, description="被核销的令牌 id；必须为链末端")
    request_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致"
    )
    reservation_key: str | None = Field(
        default=None,
        min_length=1,
        description="可选：事先预留额度的预留键；提供后即成为核销内容的一部分",
    )


class CoRedeemSide(BaseModel):
    """会签的一侧：一条链及其末端令牌。"""

    chain_id: str = Field(min_length=1, description="链 id")
    token_id: str = Field(min_length=1, description="该链末端令牌 id")


class CoRedeemRequest(RequestContext):
    """双主体会签核销请求；判定时间由服务端以接收时刻统一重算（请求体不提供时间）。

    主授权链与复核链共享同一份请求上下文（路径 / 方法 / 来源 IP / 请求体），
    两条链必须不同，且两条链末端令牌的 subject 必须不同（双主体）。
    """

    primary: CoRedeemSide = Field(description="主授权链及其末端令牌")
    review: CoRedeemSide = Field(description="复核链及其末端令牌")
    request_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致"
    )

    @model_validator(mode="after")
    def _validate_distinct_chains(self) -> "CoRedeemRequest":
        if self.primary.chain_id == self.review.chain_id:
            raise ValueError(
                "主授权链与复核链必须是两条不同的链（chain_id 不得相同）"
            )
        return self


class Check(BaseModel):
    name: str
    passed: bool
    detail: str = ""
    reason: str | None = None


class NodeTrace(BaseModel):
    token_id: str
    issuer: str
    subject: str
    parent_id: str | None
    is_root: bool
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)


class IntegrityReport(BaseModel):
    allow: bool
    first_failed_node: str | None
    first_failed_reason: str | None
    ordered_token_ids: list[str]
    trace: list[NodeTrace]


class SubmissionResult(BaseModel):
    chain_id: str
    replayed: bool
    integrity: IntegrityReport


class ChainRecord(BaseModel):
    chain_id: str
    content_sha256: str
    created_at: datetime
    integrity: IntegrityReport
    tokens: list[CapabilityToken]
    revocations: list["RevocationEvent"] = Field(default_factory=list)
    redemptions: list["RedemptionEvent"] = Field(default_factory=list)


class EvaluateResult(BaseModel):
    chain_id: str
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    body_sha256: str
    trace: list[NodeTrace]
    # 按链顺序第一个因撤销（含祖先撤销的继承）被拒绝的节点
    first_revoked_node: str | None = None


class RevocationRequest(BaseModel):
    """运维方提交的按时间生效撤销请求（chain_id 取自 URL 路径）。"""

    token_id: str = Field(min_length=1, description="被撤销的令牌 id")
    effective_at: datetime = Field(description="撤销生效时间（含时区），可指向未来")
    reason: str = Field(min_length=1, description="撤销原因（审计说明）")
    request_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致"
    )

    @field_validator("effective_at")
    @classmethod
    def _validate_effective_at(cls, v: datetime) -> datetime:
        return _ensure_aware(v, "effective_at")


class RevocationEvent(BaseModel):
    """不可变撤销事件（追加后不得修改或删除）。"""

    chain_id: str
    token_id: str
    effective_at: datetime
    reason: str
    request_key: str
    content_sha256: str = Field(description="事件规范化内容指纹，用于重放/冲突判定")
    created_at: datetime = Field(description="事件落库时间（UTC）")


class RevocationResult(BaseModel):
    replayed: bool
    event: RevocationEvent
    # 被撤销节点自身及其后代，按原链（根→叶）顺序排列
    affected_token_ids: list[str]


class RevocationImpact(BaseModel):
    """撤销事件影响清单中的一项：一笔被追溯命中的成功访问核销。

    清单在撤销事件写入的同一事务内计算并随事件保存，之后不可变；
    只投影访问的核销时间、访问键、链与末端令牌，不改写原核销记录。
    """

    request_key: str = Field(description="受影响访问（核销）的 request_key")
    chain_id: str = Field(description="受影响核销所在的链")
    token_id: str = Field(description="被核销的末端令牌")
    kind: Literal["single", "co"] = Field(
        description="single=单链核销；co=双主体会签（一笔会签只列一次）"
    )
    side: Literal["primary", "review"] | None = Field(
        default=None,
        description="会签中受影响的一侧（primary=主授权 / review=复核）；单链核销为 null",
    )
    redeemed_at: datetime = Field(description="核销时间（UTC）")


class RevocationImpactsResult(BaseModel):
    """按撤销 request_key 查询到的影响清单（无命中时 impacts 为空列表）。"""

    request_key: str = Field(description="撤销事件的 request_key")
    chain_id: str = Field(description="撤销事件所在的链")
    token_id: str = Field(description="被撤销的令牌")
    effective_at: datetime = Field(description="撤销生效时间（UTC）")
    # 按 (核销时间, 访问 request_key) 升序
    impacts: list[RevocationImpact]


class RedemptionEvent(BaseModel):
    """一次性访问核销记录（成功核销才落库；只追加、不可变）。"""

    chain_id: str
    token_id: str
    request_key: str
    request_path: str
    method: str
    source_ip: str | None
    request_body: Any
    content_sha256: str = Field(description="核销请求规范化内容指纹，用于重放/冲突判定")
    evaluated_at: datetime = Field(description="服务端接收时刻（UTC），即判定时间")
    redeemed_at: datetime = Field(description="核销成功时刻（UTC，与 evaluated_at 一致）")
    created_at: datetime = Field(description="记录落库时间（UTC）")


class QuotaIn(BaseModel):
    """为链末端 subject 设置 / 调整跨链成功核销总额度。

    ``limit`` 为非负整数：该主体此后成功核销（单链核销 + 会签中该主体参与的
    一侧，每次算一次）的总次数上限；显式传 ``null`` 清除额度，恢复不限额。
    """

    limit: int | None = Field(
        default=None,
        ge=0,
        description="成功核销总额度（非负整数）；null=清除额度、不限额（默认未设置亦不限额）",
    )


class QuotaStatus(BaseModel):
    """某链末端 subject 的额度口径：额度、已用量、有效预留与可用量。

    - ``limit`` 为 null 表示未设置额度（不限额），此时 ``remaining`` / ``available``
      也为 null；
    - ``used`` 为该主体在全部链上的成功单链核销数，加上会签中该主体参与一侧
      的次数（每笔会签对每个参与主体计一次）——包含额度设置之前的历史成功核销，
      且追溯撤销 / 停用密钥不退还历史用量；
    - ``reserved`` 为该主体当前**有效预留**数（未过期、尚未转为核销的短时预留，
      每笔预留占一份额度；过期自动释放）；
    - ``remaining`` = ``limit - used``（毛剩余，含已被预留的份额）；
    - ``available`` = ``limit - used - reserved``（普通核销 / 会签 / 新预留
      实际可用的份额）；
    - 口径持久化在数据库中，服务重启后不变。
    """

    subject: str = Field(description="链末端被授权主体名（额度按主体跨链累计）")
    limit: int | None = Field(description="成功核销总额度；null=未设置额度（不限额）")
    used: int = Field(description="历史已用量：成功单链核销 + 会签参与侧（每次算一次）")
    reserved: int = Field(
        default=0, description="有效预留数：未过期且未转为核销的短时预留（每笔占一份）"
    )
    remaining: int | None = Field(
        description="毛剩余量 = limit - used（含被预留的份额）；未设置额度时为 null"
    )
    available: int | None = Field(
        description="可用量 = limit - used - reserved；未设置额度（不限额）时为 null"
    )
    updated_at: datetime | None = Field(
        default=None,
        description="额度最近一次设置 / 调整时间（UTC）；从未设置额度时为 null",
    )


class QuotaResult(QuotaStatus):
    """额度设置 / 查询结果。"""

    # 设置 / 调整前的额度（null=此前未设置或已清除，均为不限额）
    previous_limit: int | None = Field(
        default=None, description="本次调整前的额度；null=此前不限额"
    )


class RedeemResult(BaseModel):
    """核销接口响应：无论是否核销成功都返回完整判定轨迹。"""

    chain_id: str
    token_id: str
    request_key: str
    redeemed: bool
    # 200：request_key 重放（含拒绝后换内容之外的同键重试）；201：首次成功核销
    replayed: bool = False
    evaluated_at: datetime
    redeemed_at: datetime | None = None
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    body_sha256: str
    first_revoked_node: str | None = None
    trace: list[NodeTrace]
    # 链末端 subject 成功核销总额度在“判定允许”后的结论：
    # quota_exhausted=可用额度（limit - used - reserved）已满（可核销的其他条件
    # 全部满足，但本次不核销）；null=未设置额度（不限额），或判定本身已被既有
    # 授权 / 撤销 / 停用检查拒绝（按约定只有可成功核销时才检查余额）。
    # 预留相关的拒绝（发生在授权判定之前，不计已用、不占核销键）：
    # token_reserved=目标令牌持有有效预留，普通核销不得占用（须携带对应预留键）；
    # reservation_mismatch=携带的预留键不存在 / 已过期，或链、令牌、访问内容
    # （路径 / 方法 / 来源 IP / 请求体）与预留不符。
    deny_reason: Literal[
        "quota_exhausted", "token_reserved", "reservation_mismatch"
    ] | None = None
    # 本次所检查的链末端 subject 额度口径（仅在判定允许、进行了余额检查时返回）。
    # 成功核销后为扣减后的口径；余额不足拒绝时为拒绝瞬间的口径（已用量未变）；
    # 未设置额度（不限额）或未进行余额检查时为 null。
    quota: QuotaStatus | None = None


class ReserveRequest(RequestContext):
    """短时额度预留请求：为一次单链访问预先占一份额度（有效秒数 1～300）。

    判定时间由服务端以接收时刻重算（请求体不提供时间）；仅在主体已设额度、
    授权允许、令牌未核销且可用额度充足时占一份，返回到期时间。
    """

    token_id: str = Field(min_length=1, description="预留针对的令牌 id；必须为链末端")
    reservation_key: str = Field(
        min_length=1, description="客户端幂等键；同键内容必须一致（仅有效预留占用）"
    )
    ttl_seconds: int = Field(
        ge=1, le=300, description="预留有效秒数（1～300）；到期自动释放"
    )


class ReservationEvent(BaseModel):
    """短时额度预留记录（成功预留才落库；过期自动释放，核销成功后转为已用删除）。"""

    chain_id: str
    token_id: str
    reservation_key: str
    subject: str = Field(description="预留时锁定的链末端 subject（额度按主体统计）")
    request_path: str
    method: str
    source_ip: str | None
    request_body: Any
    content_sha256: str = Field(description="预留请求规范化内容指纹，用于重放/冲突判定")
    created_at: datetime = Field(description="预留落库时间（UTC）")
    expires_at: datetime = Field(description="预留到期时间（UTC）；过期自动释放")


class ReservationResult(BaseModel):
    """预留接口响应：无论是否预留成功都返回完整判定轨迹。"""

    chain_id: str
    token_id: str
    reservation_key: str
    reserved: bool
    # 200：reservation_key 重放（同键同内容）；201：首次成功预留
    replayed: bool = False
    evaluated_at: datetime = Field(description="服务端接收时刻（UTC），即判定时间")
    expires_at: datetime | None = Field(
        default=None, description="预留到期时间（UTC）；预留失败时为 null"
    )
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    body_sha256: str
    first_revoked_node: str | None = None
    trace: list[NodeTrace]
    # 授权判定允许后的额度结论：quota_unset=主体未设额度（预留要求已设额度）；
    # quota_exhausted=可用额度（limit - used - reserved）不足；
    # null=预留成功，或判定本身已被既有授权 / 撤销 / 停用检查拒绝（不查额度）。
    deny_reason: Literal["quota_unset", "quota_exhausted"] | None = None
    # 链末端 subject 的额度口径（仅在判定允许、进行了额度检查时返回）；
    # 预留成功后为占用一份后的口径。
    quota: QuotaStatus | None = None


class CoRedemptionEvent(BaseModel):
    """双主体会签核销记录（两侧同时成功才落库；只追加、不可变）。"""
    request_key: str
    primary_chain_id: str
    primary_token_id: str
    review_chain_id: str
    review_token_id: str
    request_path: str
    method: str
    source_ip: str | None
    request_body: Any
    content_sha256: str = Field(description="会签请求规范化内容指纹，用于重放/冲突判定")
    evaluated_at: datetime = Field(description="服务端接收时刻（UTC），即两侧共同的判定时间")
    redeemed_at: datetime = Field(description="两侧共同的核销时间（UTC，与 evaluated_at 一致）")
    created_at: datetime = Field(description="记录落库时间（UTC）")

    def leg_event(self, chain_id: str) -> "RedemptionEvent":
        """投影出某一侧链视角的核销记录（供链查询与“已核销”判定复用）。"""
        if chain_id == self.primary_chain_id:
            token_id = self.primary_token_id
        else:
            assert chain_id == self.review_chain_id, "leg_event 只接受会签两侧的 chain_id"
            token_id = self.review_token_id
        return RedemptionEvent(
            chain_id=chain_id,
            token_id=token_id,
            request_key=self.request_key,
            request_path=self.request_path,
            method=self.method,
            source_ip=self.source_ip,
            request_body=self.request_body,
            content_sha256=self.content_sha256,
            evaluated_at=self.evaluated_at,
            redeemed_at=self.redeemed_at,
            created_at=self.created_at,
        )


class CoRedeemLegResult(BaseModel):
    """会签单侧的判定结果与完整轨迹。"""

    chain_id: str
    token_id: str
    subject: str = Field(description="该链末端令牌的 subject（会签要求两侧不同）")
    decision: Literal["allow", "deny"]
    first_failed_node: str | None
    first_failed_reason: str | None
    first_revoked_node: str | None = None
    trace: list[NodeTrace]
    # 既有授权 / 撤销 / 停用检查全部通过（decision=allow）后才进行的余额与预留检查：
    # 该侧主体可用额度不足时为 quota_exhausted；该侧末端令牌持有有效预留时为
    # token_reserved（会签不得占用被预留的令牌）——两种情况下本次会签两侧均不
    # 核销、不占键；null=未设置额度（不限额）且令牌无有效预留，或该侧未通过
    # 既有检查（未到余额 / 预留检查环节）。
    deny_reason: Literal["quota_exhausted", "token_reserved"] | None = None
    # 该侧末端 subject 的额度口径（仅在该侧判定允许、进行了余额检查时返回）；
    # 会签成功后为扣减后的口径；余额不足（任一侧）时为拒绝瞬间的口径；
    # 未设置额度或未进行余额检查时为 null。
    quota: QuotaStatus | None = None


class CoRedeemResult(BaseModel):
    """双主体会签响应：两份判定轨迹与共同核销时间。"""

    request_key: str
    redeemed: bool
    # 200：request_key 重放（同键同内容）；201：首次会签成功
    replayed: bool = False
    evaluated_at: datetime = Field(description="两侧共同的判定时间（服务端接收时刻，UTC）")
    redeemed_at: datetime | None = Field(
        default=None, description="两侧共同的核销时间；任一侧拒绝时为 null"
    )
    body_sha256: str
    primary: CoRedeemLegResult
    review: CoRedeemLegResult



class PrincipalIn(BaseModel):
    name: str = Field(min_length=1)
    hmac_secret: str = Field(min_length=1, description="该主体的 HMAC 密钥")


class PrincipalOut(BaseModel):
    name: str


class KeyRotationIn(BaseModel):
    """主体 HMAC 密钥轮换请求（主体名取自 URL 路径）。"""

    hmac_secret: str = Field(
        min_length=1, description="新的 HMAC 密钥；必须与当前密钥不同"
    )


class PrincipalRotationOut(BaseModel):
    """密钥轮换结果（响应不携带任何密钥材料）。"""

    name: str
    generation: int = Field(description="轮换后的当前密钥代次（注册为 1，每次轮换 +1）")
    rotated_at: datetime = Field(description="轮换生效时间（UTC）")


class KeyDeactivationIn(BaseModel):
    """疑似签发密钥失陷：停用某主体指定代次密钥的请求（主体名 / 代次取自 URL 路径）。"""

    reason: str = Field(min_length=1, description="停用原因（审计说明，非空）")


class KeyDeactivationEvent(BaseModel):
    """不可变密钥停用事件（追加后不可撤销；轮换不解除旧代次的停用）。"""

    principal: str = Field(description="被停用密钥所属的签发主体名")
    generation: int = Field(description="被停用的密钥代次")
    reason: str = Field(description="停用原因（审计说明）")
    deactivated_at: datetime = Field(description="停用生效时间（UTC，立即生效、不可撤销）")


class KeyDeactivationResult(BaseModel):
    """密钥停用结果（响应不携带任何密钥材料）。"""

    replayed: bool = Field(
        description="false=新停用事件（201）；true=同一（主体, 代次）同原因幂等重放（200）"
    )
    event: KeyDeactivationEvent


class ConflictDetail(BaseModel):
    detail: str
    chain_id: str
    existing_sha256: str
    received_sha256: str


ChainRecord.model_rebuild()
