# Performance and monomorphisation budgets

The budget harness models two hot paths present in pgcat and CipherStash Proxy:
decoding/reconstructing inspected frontend messages, and repeatedly advancing a
short pooled query session. Run it with:

```bash
cargo bench --bench protocol_budget
```

The release-mode acceptance budgets are:

- at least 100,000 complete operations/s for each workload; and
- no more than 10 MiB for the representative statically linked benchmark
  executable, which instantiates the codec and generated frontend FSM.

These intentionally broad regression limits are portable across CI runners.
Optimisation work should record distributions separately rather than weakening
correctness tests or coupling the library to a particular Proxy deployment.

## Controlled burn-in measurements

The `pg-proto-burn-in performance` command turns measurements captured through
the public intermediary harness into versioned `performance.json`, Markdown,
and an unpromoted candidate baseline. Input keeps warm-up, closed-loop, and
fixed-rate open-loop samples separate. Reports include queue, execution, raw
end-to-end, and coordinated-omission-corrected latency histograms, achieved
rate, repeated-window drift, build identity, resource-checkpoint evidence, and
COPY evidence.

Use `--build-mode optimized` with Cargo profile `burn-in`, or
`--build-mode allocator-diagnostic` with `burn-in-diagnostic`; their results are
not comparable. Thresholds remain advisory by default. `--enforce` additionally
requires `--stable-runner`, Linux, a named non-hosted runner, and a reviewed
promoted baseline. Candidate baselines are always written with
`promoted: false`; promotion is a separate reviewed operation. In particular,
ordinary hosted CI never acts as a performance gate.
