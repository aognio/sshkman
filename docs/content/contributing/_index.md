+++
title = "Contributing"
+++

# Contributing

Build and verify with:

```bash
make fmt
make lint
make test
make e2e
```

The workspace is library-first. Keep pure crates free of filesystem, network, clock, and process effects. Add tests for new behavior before claiming completion.
