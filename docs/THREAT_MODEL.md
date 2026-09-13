# Threat model

## What is being protected

An organisation has internal tools behind MCP servers — document stores,
ticketing, build systems — and wants to let an LLM agent use them. The assets
are the data those tools can reach, the destructive actions they can perform,
and the record of what was done.

## Assumed position of the gateway

Every call from the agent to an upstream passes through it. If an agent can
reach an upstream directly, none of this applies; network policy has to
guarantee that, and the gateway cannot enforce it.

## Adversaries

**A1 — A confused or over-eager model.** Not malicious. It has a tool
catalogue and a goal, and it picks the tool that looks closest. This is the
most likely adversary by a wide margin, and it is the one catalogue filtering
addresses: a tool that is never advertised is not a tool the model reaches for.

**A2 — Content planted in data the model reads.** An attacker cannot talk to
the model directly, but can put text into a document, ticket or note that the
model will later retrieve. The text is written to look like instructions.

**A3 — A caller holding a valid key for a low-privilege role.** Wants to reach
tools their role does not cover, by guessing names, by passing arguments that
make a permitted tool do more, or by volume.

**A4 — A caller holding no valid key.** Wants to authenticate by guessing, or
to learn which key ids exist.

**A5 — Someone with write access to the gateway's own storage.** Wants a past
action to disappear from the record.

## What the gateway defends against

| Threat | Control | Where |
| --- | --- | --- |
| A1 reaching for a tool it should not have | Deny-by-default authorization; the catalogue returned by `tools/list` is filtered per role | `policy.py` |
| A1 or A3 passing a permitted tool an abusive argument | Per-role and per-argument bounds on string length, collection size and enum membership, checked before forwarding | `policy.py` |
| A2 having its planted text reach the model unremarked | Injection detectors flag and audit the response; `block` mode refuses it | `scanner.py` |
| A2 or a misconfigured tool leaking a credential outward | Secret detectors redact the value and name the class | `scanner.py` |
| A3 escalating by volume | Token bucket per principal | `ratelimit.py` |
| A4 guessing a key | Secrets are stored as `sha256`; comparison is constant-time; unknown key ids take the same path and roughly the same time as wrong secrets; every failure returns the same message | `auth.py` |
| A5 editing history quietly | Hash chain over canonicalised entries, rooted in a secret-derived genesis hash; `verify` names the first row that does not reconcile; SQLite triggers reject `UPDATE` and `DELETE` | `audit.py` |
| Operator error deploying without a secret | The process refuses to start on a missing or short `MCPG_SIGNING_SECRET` — there is no insecure fallback | `config.py` |

## What it does not defend against

**Prompt injection, in general.** The detectors are regexes. They catch text
that looks like the well-known phrasings. An attacker who paraphrases, encodes,
splits across fields, or writes in a language the patterns do not cover gets
through. This layer raises the cost of the obvious attack and creates a record;
it is not a control you can rely on. If an upstream serves attacker-controlled
text, assume some of it reaches the model.

**Secrets that have no shape.** Detection is pattern matching. Internal token
formats, passwords in prose, and data that is sensitive for contextual reasons
rather than syntactic ones are invisible to it.

**A compromised or malicious upstream**, beyond what the scanner catches. The
gateway does not verify that a tool did what it claimed, and cannot.

**A stolen key, used normally.** Authorization is by role. A stolen `operator`
key is an operator until someone notices in the audit log and disables it.
There is no anomaly detection and no binding of a key to a source address.

**An attacker who holds both database write access and the signing secret.**
They can recompute a consistent chain. See AUDIT_DESIGN.md.

**Transport security.** The gateway speaks plain HTTP. TLS is the job of
whatever terminates in front of it. Keys travel in an `Authorization` header
and are only as protected as that transport.

**Denial of service.** Rate limiting is per principal and in-process. It shapes
one caller's usage; it does not protect the gateway from a flood, and two
replicas each grant a full budget.

**Side channels beyond the authentication path.** Timing was considered for key
comparison specifically. Nothing else has been analysed for it.

**The host.** Anyone who can read the container's environment holds the signing
secret. Anyone who can read `keys.json` holds the hashes, which are useless on
their own but do enumerate principals and roles.

## Residual risk worth stating plainly

The two controls most likely to be believed more than they deserve are
injection detection and the audit chain. Injection detection is a tripwire, not
a wall. The audit chain proves that a log has not been casually edited; it does
not prove that a log is complete, because an attacker who controls the process
can simply not write an entry.
