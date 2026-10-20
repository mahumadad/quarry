# Gotchas: Remote Code Execution (RCE)

## Common False Positives
- Command-injection time delay (`; sleep 10`) that is not reproducible: slow server, queued job, WAF delay.
- Output reflection of your payload (`$(id)` echoed back literally) with no evaluation.
- Error messages that mention a shell, interpreter or stack trace without evidence your input was executed.
- Version-based "RCE" from a banner (Apache, Struts, Log4j, Spring) with no triggered exploit. The component may be patched, backported or not on the vulnerable code path.
- Callback to your listener caused by a scanner/proxy/mail gateway resolving or fetching your payload URL, not the vulnerable service executing code.
- Sandboxed execution that is working as designed (online code runner, serverless function, notebook) with proper isolation and no escape.
- Template or expression evaluation that is only arithmetic (`{{7*7}}`) with no path to code execution shown: that is SSTI, scope it as such.
- Admin-only feature that intentionally runs code or plugins (e.g. CI job, plugin upload) where the actor already has the privilege.
- Scanner (Nuclei/Nessus) matching on a response string that appears in unrelated content.

## Overclaim Traps
- "Full server compromise" from `id`/`whoami` output on a low-privilege container user: describe the actual context (user, container, network reach).
- Claiming root without a privilege escalation proof.
- Claiming lateral movement, data theft or persistence without performing (and being authorized for) those steps.
- Rating authenticated admin-only RCE the same as unauthenticated RCE; reflect privileges required.
- Reporting known-CVE exposure as demonstrated RCE; label as Inferred until triggered.
- Claiming blind RCE solely from DNS interaction: also show a second independent signal (HTTP callback with command output, file write verified, timing control).
- Equating arbitrary file upload with RCE without showing the file is executed.

## Minimum Proof Required
- Exact request and payload plus the minimal, harmless command executed (`id`, `whoami`, `hostname`, `uname -a`, or writing a unique marker). Operator approval before executing any command that changes state.
- Output of the command returned in the response or retrieved through an out-of-band channel you control, containing a unique per-test token.
- Result reproduced at least twice, with a negative control (payload without the injection characters behaves differently).
- Execution context established: OS user, hostname, container indicators, working directory.
- For blind cases: OOB callback carrying command output, or a controlled timing oracle with controls.
- Cleanup note: any file or artifact created and how it was removed.

## When to Mark N/A
- No user input reaches a shell, interpreter, template engine, deserializer or code-loading mechanism (confirmed by behaviour and, if available, source).
- Component is verifiably patched or not reachable, and exploit attempts (authorized) failed.
- The target is a managed sandbox whose isolation is out of scope and no escape is in the engagement.
- Testing would be destructive or the operator declined approval: mark "Not tested", describe the hypothesis as Unproven.
