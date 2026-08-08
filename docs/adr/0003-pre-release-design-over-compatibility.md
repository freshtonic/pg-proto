# Prefer design quality over pre-release compatibility

Until CipherStash Proxy ships rewritten in terms of `pg-proto`, prefer the best `pg-proto` design over backward compatibility. The crate has no external consumers yet, so obsolete interfaces may be changed or removed without deprecation periods or compatibility adapters; revisit this decision once the rewritten Proxy ships.
