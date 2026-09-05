# AssuredDeletionPTAD

CoreLib plugin reproducing PTAD's core unlink-overwrite-verify workflow. It
provides a deterministic deletion-pattern overwrite and compact trace receipt,
and uses CoreLib's SM9 aggregate PDP chain to authenticate the resulting data.

Blockchain anchoring is intentionally not embedded in this plugin; an
application can persist `DeletionReceipt` in its chosen ledger after it stores
the updated data and authenticators.

## Build and test

```sh
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

The hot-load algorithm type is `AssuredDeletionPTAD`.
