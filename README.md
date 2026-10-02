# UnitSandboxAudit

Systemd service sandbox configuration audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"fragments":[{"name":"app.service","text":"[Service]\n..."},{"name":"10.conf","text":"[Service]\n..."}]}`. Caller supplies the authoritative selected fragment order. Scalar declarations override; supported lists append and empty lists reset. Complete new scope checks ten sandbox switches, resolved User/DynamicUser declarations, ProtectSystem/Home, capabilities, address families, private UMask, execution privilege prefixes and broad writable root paths. Missing declarations, unsupported directives, list inversions/specifiers, syscall group filters, symbolic masks and implicit identities are OPEN. This does not resolve systemd's unit search paths or score a service's effective runtime security.

## Use and output

Install `artifacts/*.whl` and run `unit-sandbox-audit examples/good.json`, or `python -m unit_sandbox_audit examples/good.json`. Output is structured JSON with individual PASS/FAIL/OPEN evidence and aggregate counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Unsupported or incomplete evidence cannot exit 0. Input is at most 2 MiB, 32 layers and 100000 nodes; duplicate keys/nonfinite numbers are rejected. The same non-following/non-blocking fd must be regular and unchanged across reading. Findings are bounded to 20000.

## Evidence and limits

`ORIGIN.md` pins exact upstream files/commit/hashes. `tests/` covers substantive parser/policy cases; `examples/expectations.json` lists expected CLI results. `VALIDATION.md` and `artifacts/validation.json` separate unit/wheel/CLI evidence from effective host behavior, upstream equivalence and CVP eligibility/approval, which remain OPEN. All processing is offline, read-only and uses supplied synthetic/public evidence.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.

The explicit address-family policy recognizes AF_UNIX, AF_INET, AF_INET6, AF_PACKET and AF_NETLINK; other families are OPEN. Numeric User values are bounded Linux UIDs and every representation of zero fails. Declared names do not establish NSS identity. ReadWritePaths uses lexical absolute-path normalization only; specifiers and unsupported forms are OPEN, and symlink destinations are not resolved.
