# Dependency locks

`requirements*.lock` pin every package **with SHA-256 hashes**, so pip runs in
hash-checking mode and refuses any artifact that does not match.

| Lock | Input | Used by |
|---|---|---|
| `requirements.lock` | `runtime.in` | Clavure runtime (CI, Duo flow environment, CLI image) |
| `requirements-build.lock` | `build.in` | installing Clavure itself with `--no-build-isolation` |
| `requirements-dev.lock` | `dev.in` | lint and tests |

Install pattern (no unpinned downloads):

```bash
pip install --require-hashes -r requirements.lock -r requirements-build.lock
pip install --no-deps --no-build-isolation .
```

Regenerate after changing an `.in` file:

```bash
for p in runtime:requirements.lock dev:requirements-dev.lock build:requirements-build.lock; do
  uv pip compile "requirements/${p%%:*}.in" --generate-hashes --python-version 3.12 \
    --no-header --quiet -o "${p##*:}"
done
```
