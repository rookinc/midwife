# Authority Roles

## xkernelorg
Role: Issuer / Root Authority

- Issues toolkits
- Signs toolkit manifests
- Publishes issuer public keys
- Never shares private keys
- Does not verify its own artifacts

## midwife
Role: Registrar / Witness

- Verifies toolkits issued by xkernelorg
- Logs births and handoffs
- Signs registry and handoff statements
- Never signs toolkit manifests
- Never possesses issuer private keys

## Agents
Role: Subjects

- Receive toolkits
- Generate their own keys
- May later request identity attestations
