# Bug tracker

- [x] Reconnects within the same second reuse the same agent topic because the ID only contains `time.Now().Unix()`. Fixed by combining nanosecond time with a process-local monotonic sequence.
- [x] The channel join accepts any `phx_reply` regardless of its `ref`, so an unrelated reply can be mistaken for successful authentication. Fixed by requiring the join request's reference.
- [x] `workerPool.submit` can send on the task channel while `stop` closes it, causing a process-ending panic when submission and shutdown race. Fixed by synchronizing submission with channel closure and rejecting work after shutdown.
