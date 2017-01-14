## Tests

```sh
cargo test -p open-ssh-core
```

The suite asserts that every registered capability appears in the report with
either an available state or one of the three stable unavailable codes, that ids
are unique, and that audit fields serialize as camelCase.

The `ssh` module also runs the client against an in-process loopback server,
including an upload and a download that are cut at a known byte and then resumed
from that exact offset.
