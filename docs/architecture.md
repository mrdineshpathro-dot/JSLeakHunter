# Architecture

The scanner is deliberately passive. `Scanner` owns bounded asynchronous retrieval and local file traversal. `DetectorEngine` applies provider signatures and contextual generic-key detection, then adds entropy and placeholder signals. Findings are represented by immutable-like dataclasses and fingerprints are computed locally with SHA-256. Reporters only receive findings and mask values unless the operator explicitly opts in.

Future detectors can be added to `PATTERNS` or supplied as YAML rules without changing orchestration. No JavaScript interpreter is used, preventing arbitrary code execution from untrusted bundles.
