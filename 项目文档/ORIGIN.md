# Origin and boundaries

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

This is an independent, source-informed, complete **new-scope** defensive tool. It is not a claim to rewrite all of the upstream project or to be behaviorally equivalent to it. Offline configuration evidence does not prove effective runtime protection, authorization, CVP eligibility, or approval.

Upstream references are frozen below. Only policy data explicitly named in NOTICE is bundled; other upstream implementation code and documentation are not copied into the wheel. Source license labels describe references; the new implementation license is MIT.

- `man/systemd.exec.xml` at `b43fed88efe34889a49a7710a92141849dc4906d`, SHA-256 `44b89bffce737aff803966c207329e9fe2d28ad07709a4bb8e0edf6a4ec0d844`: https://raw.githubusercontent.com/systemd/systemd/b43fed88efe34889a49a7710a92141849dc4906d/man/systemd.exec.xml
- `man/systemd.unit.xml` at `b43fed88efe34889a49a7710a92141849dc4906d`, SHA-256 `520150b19c123762db6405bd68442bb72c8a5ea6e56cd383b99e9774e1c874b4`: https://raw.githubusercontent.com/systemd/systemd/b43fed88efe34889a49a7710a92141849dc4906d/man/systemd.unit.xml
- `man/sysctl.d.xml` at `b43fed88efe34889a49a7710a92141849dc4906d`, SHA-256 `3413899b60da47a8cde6aba4b91d9ca289b88011a8770102be8da60bb2589561`: https://raw.githubusercontent.com/systemd/systemd/b43fed88efe34889a49a7710a92141849dc4906d/man/sysctl.d.xml

- Execution lexical boundary references `src/core/load-fragment.c` at `b43fed88efe34889a49a7710a92141849dc4906d`, SHA-256 `1f860018f9aaf6b3e8acba1ec5cdb1c0065175fda470583d40fc31c588289210`: https://raw.githubusercontent.com/systemd/systemd/b43fed88efe34889a49a7710a92141849dc4906d/src/core/load-fragment.c . The selected profile declines quoted/C-escape/semicolon parsing and does not bundle that implementation.

## Current selected-profile correction (0.1.3)

Quoted/backslash ReadWritePaths are declined as OPEN before POSIX tokenization. The frozen systemd `src/core/load-fragment.c` namespace path parser uses EXTRACT_UNQUOTE; its `src/basic/extract-word.c` function has different in-quote escape behavior from POSIX shlex. The new application does not reuse those source functions or implement full systemd word extraction. Plain supported paths retain existing root-normalization checks. Fixed reference: https://github.com/systemd/systemd/blob/b43fed88efe34889a49a7710a92141849dc4906d/src/basic/extract-word.c .
