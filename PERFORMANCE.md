# Performance and monomorphisation budgets

The budget harness models two hot paths present in pgcat and CipherStash Proxy:
decoding/reconstructing inspected frontend messages, and repeatedly advancing a
short pooled query session. Run it with:

```console
cargo bench --bench protocol_budget
```

The release-mode acceptance budgets are:

- at least 100,000 complete operations/s for each workload; and
- no more than 10 MiB for the representative statically linked benchmark
  executable, which instantiates the codec and generated frontend FSM.

These intentionally broad regression limits are portable across CI runners.
Optimisation work should record distributions separately rather than weakening
correctness tests or coupling the library to a particular Proxy deployment.
