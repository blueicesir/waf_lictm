# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.



## 5. UI Design
** Applies only to front-end design for web pages and Android applications. **
 - Reuse existing design conventions (e.g., pill toggle buttons, badge switches, or contextual setting panels) placed strictly within their most relevant sections rather than scattering unrelated controls.


## 6. Code Quality
- Prioritize root-cause, future-proof fixes rather than hardcoded logic, dead code, or speculative changes.
- Prioritize generalized solutions that cover entire classes of problems rather than one-off patches.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

Import : All temporary Python projects and related code used for verification within the project should be written and stored in the `sandbox` directory created within the project folder; do not store temporary code or data used for verification or testing haphazardly.

local tools dir:
- git.exe D:\Tools\Git\bin
- bash.exe D:\Tools\Git\bin
- golang compiler E:\Go\bin
- winrar D:\Tools\WinRAR
- python D:\Python310
- like Unix command D:\Tools\Dos
- Android Studio IDE bin Path F:\Software\Android\bin
- Dex to Java decompiler F:\Software\jadx
- github cli gh tool D:\Doc\gh.exe
- IDA Professional 9.3 terminal version D:\Tools\IDA Professional 9.3\idat.exe



## CI/CD & Build Inspection Guide

When asked to check CI/CD status, inspect build errors, or retrieve build artifacts:
1. Always use the GitHub CLI (`gh`) to query GitHub Actions:
   - Check the status of the latest run:
     `gh run list --limit 1 --json databaseId,status,conclusion,workflowName,headSha`
   - If the latest run failed, retrieve the error logs directly:
     `gh run view --log-failed`
   - To inspect a specific run's full log:
     `gh run view <run-id> --log`
   - To download generated artifacts from the latest run to `./dist` or current dir:
     `gh run download <run-id> -D ./build-artifacts`
2. Workflow for fixing build errors:
   - Identify the failed step (e.g., compile, lint, test, gradle/rustc error).
   - Locate the offending local files and lines based on the log stack trace.
   - Propose or apply the patch locally, verify the fix, and explain the root cause.