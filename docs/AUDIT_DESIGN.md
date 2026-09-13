# Audit log design

## What one row records

One row per decision, whatever the decision was. An unauthenticated attempt, a
policy denial, a rate-limited request and a successful call all produce a row.

| column | notes |
| --- | --- |
| `seq` | Monotonic, starting at 1. Gaps are a verification failure. |
| `ts` | UTC ISO-8601, millisecond precision. |
| `request_id` | The `X-Request-Id` header when present, otherwise a generated UUID. |
| `principal`, `role` | From the authenticated key. `-` when authentication failed. |
| `tool` | Tool name, or the JSON-RPC method for non-call requests. |
| `decision` | `allowed`, `denied`, `rate_limited`, `blocked`, `upstream_error`, `unauthenticated`. |
| `decision_code` | The specific rule outcome, e.g. `denied_by_rule`, `argument_too_long`. |
| `upstream` | Which upstream served it, when one did. |
| `latency_ms` | Upstream call latency. Null when no call was made. |
| `findings` | Scanner findings as `[{detector, category, severity, count}]`. |
| `prev_hash`, `hash` | The chain. |

## What is deliberately not recorded

**Tool arguments and tool results.** They are the fields most likely to contain
exactly the credentials and personal data this system exists to protect, and an
audit log is usually retained longer and read more widely than the traffic it
describes. Logging them would create a second, worse copy of the problem.

**Matched values from the scanner.** A finding records that one AWS key was
seen, not what it was. Writing the match into the log would defeat the
redaction that happened microseconds earlier.

The cost is real: you can tell that `alice` called `search_documents` and that
it was allowed, but not what she searched for. That trade is deliberate. If an
investigation needs argument-level detail, it belongs in a separate store with
its own retention and access rules, not in this one.

## The chain

```
genesis    = hmac_sha256(signing_secret, "mcpg-audit-genesis-v1")
entry_n    = {seq, ts, request_id, principal, role, tool, decision,
              decision_code, upstream, latency_ms, findings}
hash_n     = sha256(hash_(n-1) + canonical_json(entry_n))
```

`canonical_json` is `json.dumps(entry, sort_keys=True,
separators=(",", ":"), ensure_ascii=True)`. Byte stability is the entire
requirement: if the same entry ever serialises two different ways, verification
fails on honest data. Sorted keys fix ordering, the tight separators remove
whitespace variance, and `ensure_ascii` removes any dependence on the reader's
encoding.

`findings` is itself canonicalised to a JSON string before it becomes part of
the entry, so the nested structure cannot vary either.

### Why the genesis hash is derived from the signing secret

A constant genesis means anyone who can write to the database can rebuild a
consistent chain from scratch. Deriving it from the deployment secret means
they need that secret too. It also makes a chain non-portable between
deployments: copying rows from one gateway's database into another's produces a
verification failure at row 1, which is the correct outcome.

This is a modest improvement, not a qualitative one. An attacker who holds both
the database and the secret can still rewrite everything.

## Verification

`AuditLog.verify()` walks rows in `seq` order, holding the hash it expects the
next row's `prev_hash` to equal, starting from the genesis hash. It returns the
first row that fails and why. Three failures are distinguished:

- **Sequence gap** — a row was deleted or reordered.
- **`prev_hash` mismatch** — the chain was re-rooted, or a preceding row was
  removed.
- **Content mismatch** — the row's fields do not produce its stored hash. This
  is the tampering case.

`rows_checked` counts rows that verified before the failure, so `first_bad_seq`
is also the boundary between trustworthy and suspect history. Everything from
that row onward is suspect, because each hash covers the one before it.

The comparison uses `hmac.compare_digest` rather than `==`. There is no real
timing attack here — the attacker already has the database — but a hash
comparison should not be the place where that habit lapses.

## Append-only enforcement

Two SQLite triggers reject `UPDATE` and `DELETE` on the table. They stop
accidents and casual meddling through a SQL client. They do not stop an
attacker: `DROP TRIGGER` is one statement, which is exactly what the tampering
test and the README demo do. The triggers are a guard rail; the hash chain is
the actual control.

## Known gaps

**Omission is invisible.** The chain proves no recorded row was altered. It
proves nothing about a row that was never written. An attacker who controls the
gateway process can decline to log, and verification will pass.

**A whole-chain rewrite is possible** for anyone holding the database and the
secret, as above.

**There is no external anchor.** Periodically publishing the head hash
somewhere the gateway cannot write — an append-only object store, a colleague's
inbox, a transparency log — would bound how far back a rewrite could reach.
That is the obvious next step and is not implemented.

**Verification is O(n) over the whole log** and runs synchronously in the
request handler for `/audit/verify`. Fine for a demo, wrong for a log with
millions of rows.
