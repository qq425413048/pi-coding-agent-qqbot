/**
 * 敏感信息脱敏。
 *
 * 长任务心跳与 showProcess 摘要会把工具调用参数展示到 QQ 聊天里，
 * 其中可能包含密码、访问令牌、API Key 等。这里在**出站前**统一做一次
 * 文本替换，避免把凭据泄漏到聊天记录。
 *
 * 说明：这是启发式规则，不是万无一失的保险。目标是把常见形态
 * （sudo -S 密码、export TOKEN=、--password/--token、ghp_/sk- 前缀、
 * Bearer 头等）替换成 ***，降低误发风险。
 */

const RULES: Array<[RegExp, string]> = [
	// echo 'secret' | sudo -S ...
	[/(echo\s+)(['"])([^'"]{1,160})\2(\s*\|\s*(?:sudo|doas)\s+-S)/g, "$1$2***$2$4"],
	// export FOO_TOKEN=... / export FOO_SECRET=... / export FOO_KEY=...
	[
		/(export\s+[A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASS|PWD|CRED)[A-Za-z0-9_]*\s*=\s*)(['"]?)[^\s'"]+\2/gi,
		"$1$2***$2",
	],
	// Authorization: Bearer <token>（必须排在通用 key 规则之前）
	[/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1"],
	// --password xxx / --token=xxx / password: xxx / api_key=xxx / clientSecret=xxx
	[
		/((?:--?[\w-]*(?:pass(?:word|wd)?|token|secret|key)|password|passwd|token|secret|api[_-]?key|apikey|client[_-]?secret|credential|authorization)\s*[=:]\s*)(['"]?)[^\s'"}]{3,}\2/gi,
		"$1$2***$2",
	],
	// 常见令牌前缀
	[/\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}/g, "***"],
	[/\bsk-[A-Za-z0-9:_-]{8,}/g, "***"],
	[/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, "***"],
	[/\bAKIA[0-9A-Z]{16}\b/g, "***"],
	// URL 内嵌凭据 scheme://user:pass@host
	[/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)[^\s@/]+(@)/gi, "$1***$2"],
];

/** 对一段文本做敏感信息脱敏。 */
export function redactSecrets(text: string): string {
	let out = text;
	for (const [pattern, replacement] of RULES) out = out.replace(pattern, replacement);
	return out;
}
