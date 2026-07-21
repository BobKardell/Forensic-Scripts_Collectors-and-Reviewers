Live Evidence Collector v1.7

Amcache changes:
- Failed intermediate methods are logged as notices, not collection errors, when a later fallback succeeds.
- Amcache LOG1 and LOG2 are treated as optional. Missing logs are not errors.
- Present transaction logs use esentutl first, then normal/robocopy backup-mode copying.
- collection_errors.csv records only final acquisition failures.

Run as Administrator for protected live-system artifacts.
