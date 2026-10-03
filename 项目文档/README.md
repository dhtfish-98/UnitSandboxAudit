> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# UnitSandboxAudit

Version **0.1.3**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

Systemd service sandbox configuration audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"fragments":[{"name":"app.service","text":"[Service]\n..."},{"name":"10.conf","text":"[Service]\n..."}]}`. Caller supplies the authoritative selected fragment order. Scalar declarations override; supported lists append and empty lists reset. Complete new scope checks ten sandbox switches, declared User/DynamicUser values, ProtectSystem/Home, capabilities, address families, private UMask, execution privilege prefixes and broad writable root paths. Missing declarations, unsupported directives, list inversions/specifiers, syscall group filters, symbolic masks and implicit identities are OPEN. This does not resolve systemd's unit search paths or score a service's effective runtime security.

## Use and output

Install `artifacts/*.whl` and run `unit-sandbox-audit examples/good.json`, or `python -m unit_sandbox_audit examples/good.json`. Output is structured JSON with individual PASS/FAIL/OPEN evidence and aggregate counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Unsupported or incomplete evidence cannot exit 0. Input is at most 2 MiB, 32 layers and 100000 nodes; duplicate keys/nonfinite numbers are rejected. The same non-following/non-blocking fd must be regular and unchanged across reading. Findings are bounded to 20000.

## Evidence and limits

`ORIGIN.md` pins exact upstream files/commit/hashes. `tests/` covers substantive parser/policy cases; `examples/expectations.json` lists expected CLI results. `VALIDATION.md` and `artifacts/validation.json` separate unit/wheel/CLI evidence from effective host behavior, upstream equivalence and CVP eligibility/approval, which remain OPEN. All processing is offline, read-only and uses supplied synthetic/public evidence.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

Execution-prefix checks support unquoted, unescaped single command lines. Any quote, backslash or semicolon in an ExecStart/Pre/Post value is OPEN: systemd applies unquoting/C escapes before prefixes and supports legacy semicolon command separators, which this profile does not implement.

ReadWritePaths assignments containing single quotes, double quotes or backslashes remain OPEN before list tokenization. The selected plain unquoted absolute-path profile still normalizes `/../` to `/` and rejects broad writable roots. This conservative boundary avoids applying POSIX shlex semantics to systemd's distinct EXTRACT_UNQUOTE rules; it does not implement the full systemd interpreter.
