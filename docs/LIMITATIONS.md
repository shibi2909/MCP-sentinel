# Known limitations and future work

Stated plainly so that no claim in the project goes beyond what is implemented.

## Scope of the implementation
1. **Demo MCP servers run in-process.** The gateway talks to them with the official MCP SDK client
   and a real MCP handshake, but over the SDK's in-memory transport, not over the network. Adding a
   remote server over Streamable HTTP or stdio only requires another `mcp.Client` transport;
   this was not built or tested.
2. **The gateway exposes a JSON-RPC endpoint modelled on MCP `tools/list` / `tools/call`,** not a full
   MCP server (no `initialize` handshake, resources, prompts or sampling towards the agent). Real MCP
   desktop clients would need a small stdio/HTTP MCP adapter in front of it (future work).
3. **Kubernetes and Hyperledger Fabric are not implemented.** Dockerfiles and a `docker-compose.yml`
   are provided as a starting point but were **not build-tested** (Docker Desktop was not running). Anchoring the latest
   audit hash on a permissioned ledger (Fabric) is future work.

## Security limitations
4. **Pattern-based input validation** can be bypassed by obfuscation (unusual encodings, splitting
   payloads across arguments) and can produce false positives on legitimate text.
5. **The audit chain detects modification, deletion and reordering of individual records,** but an
   attacker with full write access to the database *and* the code could recompute the whole chain.
   External anchoring (WORM storage, a ledger, or periodically publishing the latest hash) would close this.
6. **The sandbox (M5) is demonstration-grade.** Python audit hooks are not a security boundary,
   and there are no CPU/memory limits on Windows beyond the timeout. Production use requires
   containers, gVisor or Firecracker micro-VMs.
7. **Tool sensitivity, trust levels and risk weights were set by hand.** They are explainable but
   not empirically calibrated.
8. **Demo credentials and API keys are published in the README;** they must be changed for any
   real deployment. There is no user management UI, key rotation or rate limiting at the HTTP layer.
9. JWTs are stored in browser `localStorage` (simple for a demo; HttpOnly cookies are safer against XSS).

## Machine learning limitations
10. **The classifier is trained on synthetic data** generated from documented assumptions. Its
    metrics (accuracy, ROC AUC, …) describe performance on held-out *synthetic* samples only and are
    not evidence of real-world detection performance. In the experiment, the ML component sometimes
    *lowers* scores compared with rules alone (configuration B is not better than A in detection).
11. The model is a linear Logistic Regression on 10 hand-made features; no online learning, drift
    detection or adversarial robustness.

## Controller and evaluation limitations
12. **The controller is a heuristic PI controller** without a formal plant model; stability is
    guaranteed by clamping (boundedness), not proven with control-theoretic analysis such as
    Lyapunov or root-locus methods. Steps are per request (event-driven), not per unit of time.
13. **Controller gains were tuned with the same seeds used for the multi-seed comparison,** so the
    comparison is not an independent test set.
14. **Experiment traffic is synthetic** and ground truth comes from the generator. The detectors
    were designed with similar attack types in mind, so absolute numbers are optimistic. Attacks
    without input signal (low-and-slow enumeration) are missed by all configurations.
15. A controller in LOCKDOWN increases the approval workload for humans; the experiment counts
    REQUIRE_APPROVAL as "caught" but does not model human reviewer cost or latency.

## Engineering limitations
16. SQLite with a process-level lock for audit appends: suitable for a single backend process,
    not for horizontally scaled deployments (use PostgreSQL and database-level sequencing).
17. The integrity check calls `tools/list` on every request (simple and always fresh, but adds latency;
    caching with notification-based invalidation would be needed at scale).

## Future work
* MCP-native front end (stdio / Streamable HTTP server) so unmodified MCP clients can connect.
* Kubernetes deployment with network policies; per-tool container sandboxes.
* Hyperledger Fabric (or other ledger) anchoring of audit-chain checkpoints.
* Real-world labelled dataset and a calibrated, periodically retrained model.
* Model-based controller design (system identification of the risk dynamics) and formal stability analysis.
* Behavioural baselining per agent (sequence models) to detect low-and-slow attacks.
