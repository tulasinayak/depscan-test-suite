# depscan-test-suite

Test repositories with known answers for depscan (a dependency CVE scanner with
an LLM exploitability step). Every repo has a `.depscan/expected.yaml` with:

- `advisories`: one label per advisory OSV returns for its pins (after depscan's alias dedup):
  `likely_affected` / `likely_not_affected` / `uncertain`, with scenario, reason and key location;
- `expected_dependencies` (optional): name, resolved version (or null), scope, direct, match, project, which scores RepoMapper;
- `expected_sites` (optional): package, file:line, symbol, which scores UsageLocator recall/precision. A site is
  a line that names an imported package symbol, or an alias/instance created from one
  (`s = requests.Session(); s.get()`, `f = getattr(idna, "encode"); f()`). Methods called on plain return values
  (`with Image.open(f) as im: im.thumbnail()`) are not counted.

depscan never reads `.depscan/` while analyzing (it is skipped like `.git/`), so the answers cannot leak into a
prompt. The application code, READMEs and commit messages contain no hints.

## Repos

| Repo | What it tests | Advisories (affected / not / uncertain) | Sites | Deps | Scenarios |
|---|---|---|---|---|---|
| [depscan-test-clean](https://github.com/tulasinayak/depscan-test-clean) | false positives and the GUI's empty state: every pin has no advisory | 0 (0 / 0 / 0) | - | 8 | - |
| [depscan-test-manifests](https://github.com/tulasinayak/depscan-test-manifests) | RepoMapper stress test: Poetry groups/extras/markers, lockfile vs pyproject, -r/-c, git/path/editable, ranges | 0 (0 / 0 / 0) | - | 25 | - |
| [depscan-test-indirection](https://github.com/tulasinayak/depscan-test-indirection) | UsageLocator: re-export, wrapper method, getattr, importlib, star import, lambda (all reachable) | 6 (6 / 0 / 0) | 18 | 7 | call_inside_lambda, getattr_lookup, importlib_import_module, reexport_through_own_module, star_import, wrapper_class_method |
| [depscan-test-reachability](https://github.com/tulasinayak/depscan-test-reachability) | the original mix: reachable, imported-but-unused, tests-only, dev-only, never imported | 15 (2 / 13 / 0) | - | - | declared_never_imported, dev_only_dependency, imported_feature_unused, reachable_untrusted_input, vulnerable_call_only_in_tests |
| [depscan-test-transitive](https://github.com/tulasinayak/depscan-test-transitive) | no_direct_usage + required_by: urllib3/certifi judged through requests | 10 (4 / 6 / 0) | 2 | 12 | certifi_removed_root_via_parent, not_reachable_via_parent, reachable_via_parent |
| [depscan-test-safe-args](https://github.com/tulasinayak/depscan-test-safe-args) | same call sites as unsafe-args, safe arguments (SafeLoader, verify=True) | 4 (0 / 4 / 0) | 7 | 3 | imported_feature_unused, safe_arguments |
| [depscan-test-unsafe-args](https://github.com/tulasinayak/depscan-test-unsafe-args) | same files as safe-args, unsafe arguments (FullLoader, first verify=False) | 4 (2 / 2 / 0) | 7 | 3 | imported_feature_unused, unsafe_arguments |
| [depscan-test-dead-code](https://github.com/tulasinayak/depscan-test-dead-code) | over-flagging: vulnerable calls that exist but never run (plus a config flag -> uncertain) | 5 (0 / 4 / 1) | 13 | 6 | dead_function, feature_flag_default_off, if_false_branch, unimported_module, unreachable_after_return |
| [depscan-test-native-reachable](https://github.com/tulasinayak/depscan-test-native-reachable) | bundled native libs reached: Image.open on uploads, PKCS#7/PKCS#12 parsing | 29 (5 / 23 / 1) | 9 | 3 | api_not_used, native_bundle_uncertain, native_reachable, native_unreachable, reachable_decoder, reachable_parser |
| [depscan-test-native-unreachable](https://github.com/tulasinayak/depscan-test-native-unreachable) | same pins, native libs not reached: Image.new + PNG, Fernet only | 29 (0 / 29 / 0) | 10 | 3 | api_not_used, native_unreachable |
| [depscan-test-monorepo](https://github.com/tulasinayak/depscan-test-monorepo) | two services pin different versions of one package; per-project reporting | 1 (1 / 0 / 0) | 2 | 4 | monorepo_per_service_version |

Total: 103 labelled advisories
(20 likely_affected, 81 likely_not_affected, 2 uncertain),
68 expected usage sites, 74 expected dependencies.

## Run

```bash
cd vul_ai   # the depscan checkout
uv run python -m depscan.cli evaluate-suite ../depscan-test-suite/suite.yaml --no-llm        # deterministic, about 1 min
uv run python -m depscan.cli evaluate-suite ../depscan-test-suite/suite.yaml                 # + LLM, both modes (hours on CPU)
uv run python -m depscan.cli evaluate-suite ../depscan-test-suite/suite.yaml --only depscan-test-safe-args,depscan-test-unsafe-args
```

Results are saved as `results/suite_eval_<timestamp>.json` / `.md` and shown on the GUI's **Suite** page.

## Where a suggested scenario did not hold

- **transitive:** a manually set `Cookie` header + redirects through **requests** is *not* affected by urllib3's
  CVE-2023-43804: requests passes `redirect=False` to urllib3 and pops `Cookie` before each redirect. It is kept as a
  tricky `likely_not_affected`; the urllib3 decompression advisories are the reachable-through-requests cases.
- **safe/unsafe args:** no Jinja2 advisory is triggered by an `Environment` argument, so the second argument-only case
  is requests `verify=`.
- **native:** cryptography 41 parses X.509 in Rust, so loading PEM certificates does not reach any bundled-OpenSSL
  advisory for that version; PKCS#7 (CVE-2023-49083) and PKCS#12 (CVE-2024-0727) parsing are the reachable cases.
- **indirection:** `importlib.import_module("sqlparse")` became pygments (every vulnerable sqlparse has 5-8 advisories).

