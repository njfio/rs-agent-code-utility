### Feature: per-request deadlines (`deadline_ms`) — bounded query latency

Any daemon request may now carry an optional top-level `deadline_ms`
(1..=600000). When the budget elapses the daemon trips the request's
cooperative `CancelToken` and returns the new `DEADLINE_EXCEEDED` error
(distinct from `CANCELLED`, so a timeout is tellable from an explicit
`Daemon.Cancel`). rts-mcp stamps a default from `RTS_DEADLINE_MS`
(default `30000`; `0` disables) on agent queries so latency is bounded
out-of-the-box; `Workspace.Mount` is exempt from the default (cold-walk
on a large repo can legitimately take minutes) but honors an explicit
`deadline_ms`. New capability `request_deadlines`; `Daemon.Stats` gains
`deadlines.total`. Additive — clients that omit `deadline_ms` are
unaffected.
