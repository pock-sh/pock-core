# Security policy

## Reporting a vulnerability

Email <security@pock.sh>. Include the affected version or commit, what an
attacker gains, and the smallest reproduction you have. A proof-of-concept
against the crate's public API is more useful than a description.

Do not open a public issue for a vulnerability. Do not test against
production Pock accounts that are not yours.

## What to expect

- Acknowledgement within 3 working days.
- An assessment, and a fix or a rejection with reasoning, within 30 days for
  anything we can reproduce.
- Coordinated disclosure up to 90 days from the report. After a fix ships we
  publish the details, and we will credit you unless you ask otherwise.

If we go quiet past 90 days, publish.

## Scope

In scope: everything in this repository — the crate, the WebAssembly and Swift
bindings, and the build scripts that produce released artifacts.

Out of scope here: the Pock web app, API, CLI, and desktop app. Report those to
the same address, but say which surface you mean.

## Bounty

There is no bug bounty program yet.

## Supported versions

The latest release only. Fixes go into a new version rather than into patches
of older ones.
