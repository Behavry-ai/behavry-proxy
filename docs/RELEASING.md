# Releasing

Releases publish to PyPI from GitHub Actions using **Trusted Publishing**
(OIDC). There is no API token: PyPI verifies a short-lived identity token
describing the repository, workflow file and environment that requested the
upload, so no long-lived credential is stored in the repo, in Actions secrets,
or on anyone's laptop.

The workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## One-time setup

This has to be done once, by someone with permission to create the project on
PyPI. It cannot be done from CI.

1. Go to <https://pypi.org/manage/account/publishing/>.
2. Add a **pending publisher** (the package does not exist yet; PyPI creates
   it on the first successful upload):

   | Field | Value |
   |---|---|
   | PyPI project name | `behavry-proxy` |
   | Owner | `Behavry-ai` |
   | Repository name | `behavry-proxy` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. Repeat on <https://test.pypi.org/manage/account/publishing/> with
   environment name `testpypi`, so dry runs work.
4. Optionally create the `pypi` and `testpypi` environments under
   **Settings → Environments** in GitHub and add required reviewers. The
   workflow references them either way; protection rules just mean a release
   waits for an approval click.

All four fields must match exactly, including the environment name — PyPI
checks them against the OIDC token and rejects anything that differs.

## Cutting a release

### 1. Dry run to TestPyPI

Worth doing the first time, and after any change to packaging or metadata.
**A version can never be re-uploaded to PyPI**, so this is the only way to
exercise the real upload path without burning the number.

**Actions → Release → Run workflow**, target `testpypi`.

Then check the result installs:

```bash
python -m venv /tmp/t && /tmp/t/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  behavry-proxy
/tmp/t/bin/behavry-proxy --version
```

The extra index is needed because TestPyPI does not mirror dependencies.

### 2. Bump the version

The version is declared in **four** places and they must agree:

- `pyproject.toml` → `[project].version`
- `behavry_proxy/__init__.py` → `__version__`
- `server.json` → `version`
- `server.json` → `packages[].version`

`scripts/check_version.py` enforces this, and CI runs it on every pull
request. Run it yourself after bumping:

```bash
python scripts/check_version.py --expect 0.2.0
```

### 3. Tag

```bash
git tag v0.2.0
git push origin v0.2.0
```

The tag triggers the release workflow, which:

1. runs the full CI gate (tests on 3.11/3.12/3.13, policy checks, the
   standalone wheel check) — reused from `ci.yml` rather than duplicated;
2. asserts the tag matches the declared version;
3. builds, runs `twine check --strict`, and confirms the
   `<!-- mcp-name: ai.behavry/proxy -->` marker survived into the wheel
   metadata;
4. publishes to PyPI.

A tag that disagrees with the declared version fails at step 2, before
anything is uploaded.

## The MCP registry

The registry stores metadata only and requires the package to exist on PyPI
first. It verifies ownership by fetching the published description and looking
for the `<!-- mcp-name: ai.behavry/proxy -->` marker, which lives at the top of
`README.md` and reaches PyPI as the long description. The release workflow
checks the marker is present in the built metadata, because losing it is
silent until the registry rejects the submission.

Once the package is on PyPI, submit `server.json` to the registry.

## If a release goes wrong

- **Yanking**, not deleting, is the remedy for a bad release — `pip` stops
  resolving a yanked version for new installs while existing pins keep
  working. Do it from the PyPI project page.
- **The version number is spent either way.** Fix forward with a patch
  release; the same number can never be re-uploaded.
