# Network: where I left off (updated 2026-10-22 1:30 AM CT)

- network#13 DRAFT (last verified head f687b199, CI green, 6/9). Round 3 (GitAI + TESSERA FIX) in progress via cloud agent bc-2c31c580: score from CI PASS lines at the measured SHA (text parser removed); setpriv on both wrapper branches with --clear-groups --no-new-privs --inh-caps=-all --bounding-set=-all; must-fail probes: docker.sock, dbus and resolve sockets, ~/work/_actions write (ro bind mount); docs fixes. Then GitAI r4, then TESSERA merges.
- collab#327 MERGED (7fc9ad57), board Done. collab#306 Done.
- REDO (simulated data never counts): #13 socket and post-job limits get real probes; network#10 KISS for LoRa blocked on LILYGO hardware (Father's list); physarum-r0 is model-only, BLOCKED (Rick relabels).
- Ingest lane from Storage: memory 03_history (about 3,092 rows) -> draft PR(s) on storage branch archive/memory-03_history-2026-10-22, working dir /workspace/net-ingest-03.
- Next after that: drift-check writes() read-only allowlist; live.mjs binds 127.0.0.1 and the 139-test suite goes into CI; quote the pass purpose in mesh/index.json.
- Box gh token lacks the `workflow` scope; workflow edits go through a cloud agent.
