package main

import (
	"route-monitor/internal/routebridge"
)

const correctionConfirmDelay = 180
const correctionEvidenceAge = 15 * 60
const correctionDailyProbes = 24
const correctionDailyChanges = 3
const correctionCooldown = 24 * 60 * 60

func eligibleFault(f Fault) string {
	if !routebridge.ValidDomain(f.Domain) {
		return "private_or_invalid_domain"
	}
	if f.Network != "tcp" || f.Port != 443 {
		return "unsupported_transport"
	}
	if f.Route != "DIRECT" && f.Route != "JP" && f.Route != "HK" {
		return "unknown_exit"
	}
	switch f.Error {
	case "DNS 解析错误", "连接超时", "连接被拒绝", "连接被重置":
		return ""
	default:
		return "unsupported_error"
	}
}

func assessRound(f Fault, e Evidence, controls []string) Decision {
	if code := eligibleFault(f); code != "" {
		return Decision{Code: code}
	}
	if len(controls) != 2 || len(e.Samples) != 12 || e.Snapshot.ID == "" || e.Finished < e.Started || e.Finished-e.Started > 75 {
		return Decision{Code: "incomplete_evidence"}
	}
	type status struct{ ok, failed bool }
	routes := map[string]status{}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		result := status{ok: true, failed: true}
		seen := map[int]bool{}
		baseline := map[string]bool{}
		for _, s := range e.Samples {
			if s.Route != route {
				continue
			}
			if s.NodeHash == "" || s.NodeHash != e.Snapshot.NodeHashes[route] || s.Time < e.Started || s.Time > e.Finished {
				return Decision{Code: "mixed_evidence"}
			}
			if s.Control {
				if s.Domain != controls[0] && s.Domain != controls[1] || baseline[s.Domain] {
					return Decision{Code: "incomplete_evidence"}
				}
				if s.Status != "response" || s.Stage != "http" || s.HTTPStatus < 100 || s.HTTPStatus > 599 {
					return Decision{Code: "exit_unhealthy"}
				}
				baseline[s.Domain] = true
				continue
			}
			if s.Domain != f.Domain || s.Round < 1 || s.Round > 2 || seen[s.Round] {
				return Decision{Code: "mixed_evidence"}
			}
			seen[s.Round] = true
			if s.Status == "unsafe" {
				return Decision{Code: "unsafe_target"}
			}
			if s.Status == "unknown" {
				return Decision{Code: "probe_unknown"}
			}
			result.ok = result.ok && s.Status == "response" && s.HTTPStatus >= 200 && s.HTTPStatus < 400
			result.failed = result.failed && s.Status == "failed" && (s.Stage == "dns" || s.Stage == "connect" || s.Stage == "tls" || s.Stage == "http")
		}
		if len(seen) != 2 || len(baseline) != 2 {
			return Decision{Code: "incomplete_evidence"}
		}
		routes[route] = result
	}
	d, j, h := routes["DIRECT"], routes["JP"], routes["HK"]
	if d.failed && j.ok && h.ok {
		if f.Route == "DIRECT" {
			return Decision{Action: "PROXY", Code: "direct_failed_proxy_usable"}
		}
		return Decision{Code: "already_proxy"}
	}
	if d.ok && j.failed && h.failed {
		if f.Route != "DIRECT" {
			return Decision{Action: "DIRECT", Code: "proxy_failed_direct_usable"}
		}
		return Decision{Code: "already_direct"}
	}
	if j.ok != h.ok || j.failed != h.failed {
		return Decision{Code: "exit_specific"}
	}
	if d.ok && j.ok && h.ok {
		return Decision{Code: "healthy"}
	}
	if d.failed && j.failed && h.failed {
		allDNS := true
		for _, s := range e.Samples {
			if !s.Control {
				allDNS = allDNS && (s.DNSStatus == "nxdomain" || s.DNSStatus == "no_address")
			}
		}
		if allDNS {
			return Decision{Code: "no_public_resolution"}
		}
		return Decision{Code: "all_paths_failed"}
	}
	return Decision{Code: "http_or_mixed_result"}
}

func assessEvidence(f Fault, rounds []Evidence, controls []string, now int64) Decision {
	if len(rounds) == 0 {
		return Decision{Code: "awaiting_evidence"}
	}
	latest := rounds[len(rounds)-1]
	if latest.Finished > now || now-latest.Finished > correctionEvidenceAge {
		return Decision{Code: "stale_evidence"}
	}
	d := assessRound(f, latest, controls)
	if d.Action == "" {
		return d
	}
	if len(rounds) < 2 {
		d.Code = "awaiting_confirmation"
		return d
	}
	previous := rounds[len(rounds)-2]
	if latest.Started-previous.Finished < correctionConfirmDelay || now-previous.Finished > correctionEvidenceAge {
		return Decision{Code: "confirmation_window"}
	}
	if previous.Snapshot.ID != latest.Snapshot.ID {
		return Decision{Code: "configuration_changed"}
	}
	first := assessRound(f, previous, controls)
	if first.Action != d.Action {
		return Decision{Code: "inconsistent_rounds"}
	}
	d.Confirmed = true
	return d
}

var correctionReasons = map[string]string{
	"checking_change":         "分时证据已确认，正在校验规则与终端配置",
	"ready_to_publish":        "发布前检查通过，等待发送调整请求",
	"no_public_resolution":    "三路解析均无可用公网地址，暂不换路；新错误可在一天后重新触发",
	"another_change_pending":  "等待上一项调整完成应用与验证",
	"cloud_unauthorized":      "规则服务授权未通过，尚未发布",
	"rules_token_unavailable": "本机规则服务凭据不可用或权限不正确",
	"cloud_invalid_response":  "规则服务返回的数据不完整，暂停继续操作",
	"runtime_file_mismatch":   "路由器保存配置与实际内核不一致，暂停自动操作",
	"snapshot_changed":        "路由器配置或节点已变化，需要重新取证",
	"configuration_busy":      "路由器正在进行另一项配置更新，稍后重试",
	"non_rules_changed":       "候选会改变规则之外的配置，已停止应用",
	"unsupported_rule":        "现有规则包含尚不支持验证的语法，保留当前配置",
	"generation_failed":       "路由器配置生成未通过，未加载候选",
	"core_validation_failed":  "内核未通过候选配置校验",
	"supported_doh_required":  "需要可验证的现有 DoH 上游进行独立解析",
	"explicit_dns_policy":     "域名有专门的 DNS 或 hosts 配置，保留其现有解析策略",
	"probe_core_failed":       "隔离探测进程未能启动",
	"probe_core_timeout":      "隔离探测进程启动超时",
	"awaiting_evidence":       "等待符合条件的新错误", "awaiting_confirmation": "初测有稳定差异，等待分时确认",
	"direct_failed_proxy_usable": "两轮直连均失败，JP/HK 均返回成功响应", "proxy_failed_direct_usable": "两轮代理均失败，直连均返回成功响应",
	"private_or_invalid_domain": "局域网或无法验证的域名，不自动调整", "unsupported_transport": "首版仅自动判断 TCP 443，其他协议保留人工检查",
	"unknown_exit": "无法可靠识别实际出口", "unsupported_error": "此类错误不能自动归因于分流",
	"incomplete_evidence": "探测证据不完整", "mixed_evidence": "探测节点、域名或时间不一致", "exit_unhealthy": "对照目标也失败，先检查出口或整体网络",
	"unsafe_target": "解析或证书不满足探测要求", "probe_unknown": "探测结果无法判断", "already_proxy": "已走代理，差异不支持重复添加规则",
	"already_direct": "已走直连，差异不支持重复添加规则", "exit_specific": "不同代理出口结果不一致，不修改共享域名规则",
	"healthy": "三条路径都可用，保持现状", "all_paths_failed": "三条路径都失败，不能通过换路解决", "http_or_mixed_result": "HTTP 状态或重复结果不足以支持自动调整",
	"stale_evidence": "证据已过期，需要重新复测", "confirmation_window": "两轮间隔或有效期不满足要求", "configuration_changed": "配置或节点已改变，重新收集证据",
	"inconsistent_rounds": "两轮结果不一致", "observe_only": "证据已确认；观察模式不会发布规则", "rules_not_configured": "已形成建议；规则服务尚未配置",
	"cloud_unavailable": "无法确认云端规则状态", "bridge_unavailable": "路由器探测程序不可用", "local_rule_protected": "与路由器人工规则冲突，未覆盖",
	"cloud_conflict": "云端修订或人工规则有冲突，未覆盖", "subscription_drift": "路由器与云端基线不一致，暂停自动应用",
	"publish_unknown": "发布结果尚未确认，正在查询原请求回执", "published": "规则已发布，等待终端应用",
	"applying": "正在应用并核对路由器规则", "applied": "路由器已加载，等待路径复验", "watching": "路径复验通过，等待真实设备连接证据",
	"confirmed": "已加载、路径复验通过，并观察到新路径接收数据；不等同 App 业务验收",
	"rollback":  "检测到回归，正在撤销本次自动调整", "rolled_back": "本次自动调整已撤销并恢复终端规则",
	"manual_intervention": "规则已被其他操作改变，保留当前配置并等待人工处理", "cooldown": "本次故障已结束，冷却后可由新错误重新触发",
	"daily_limit": "达到当日自动探测或发布上限", "interrupted": "上次探测中断，将按限流重新确认", "no_recent_fault": "没有足够的新错误，本轮结束",
	"apply_failed": "终端应用未通过；先确认现场状态，再决定撤回", "verification_failed": "修改后的路径复验失败，等待确认是否回滚",
}

func correctionReason(code string) string {
	if s := correctionReasons[code]; s != "" {
		return s
	}
	return "操作未完成（" + code + "）"
}
