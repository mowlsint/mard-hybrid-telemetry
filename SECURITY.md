# Security Policy

This repository is public by design.

Do not commit:

- API keys
- private indicators that identify victims or protected systems
- operational law-enforcement or government-only data
- personal data
- classified or restricted material

Optional API keys must be stored as GitHub Actions secrets, for example:

```text
ABUSECH_AUTH_KEY
```

The default v0.1 mode works without secrets.
