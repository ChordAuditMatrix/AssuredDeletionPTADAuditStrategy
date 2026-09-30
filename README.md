# AssuredDeletionPTAD

CoreLib plugin reproducing PTAD's unlink, overwrite, trace-receipt, proof, and
verification workflow. Its deletion state and audit artifacts are implemented
inside this repository through CoreLib's generic strategy interfaces; it does
not use a sibling audit-strategy implementation as a cryptographic backend.

Blockchain anchoring is intentionally not embedded in this plugin; an
application can persist `DeletionReceipt` in its chosen ledger after it stores
the updated data and authenticators.

## CoreLib lifecycle

Use the standard `TagGen -> Maintenance(Update) -> Challenge -> Proof ->
Verify` lifecycle in one `AuditEngine` process.  The Update request carries
the deletion intent explicitly:

```json
{
  "fileId": "object-001",
  "opType": 0,
  "deletionMode": true,
  "targetBlockIndices": [3, 7, 11],
  "seed": 20260930
}
```

`opType: 0` is CoreLib's `MaintenanceOpType::Update`.  Explicit `Delete`
requests remain supported.  An Update without `deletionMode: true` is rejected
so that ordinary dynamic-data updates cannot be mistaken for deletion.

## Build and test

```sh
git submodule update --init --recursive
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

Only `3rdparty/CoreLib` is required. The hot-load algorithm type is
`AssuredDeletionPTAD`.
