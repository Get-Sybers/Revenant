# Ansible Role & Collection Robustness Review

The robustness review checklist for every role and collection of Ansible in this
repo. It reviews for **robustness**, not style. A role is robust when it fails fast
with a clear message on bad input, is idempotent on repeat runs, survives `--check`,
and does not silently do the wrong thing on an unsupported platform.

---

## Audit criteria

For each role, check every item and record: `PASS` / `FAIL` / `N/A` with file and
line references. Severity is mine to act on, but assign a suggested one:
`critical` (silently wrong behaviour), `major` (fails unhelpfully), `minor` (hygiene).

### A0. Separation of logic and action — check this first

The one-action rule: **a task does one action
and contains no logic; the logic lives in the playbook.** Playbook decides → role
groups → task acts. Inventories supply what the playbook reasons over — dynamic
for range, static for infra.

0.1 **`when:` on an action task is a `major` finding.** Count them. Report the
    ratio of `when:` on action tasks against `when:` on
    `include_tasks`/`include_role`/`block`/play — the latter are correct, that is
    a decision sitting where decisions belong. A role whose conditionals live
    mostly on actions has its architecture inverted, and that is the finding to
    lead with, ahead of anything in §A–§H.

0.2 **A task that both detects and acts is a `major` finding.** "Install X *then*
    Y", "ensure enabled *and* running", "detect *and* select" — a fused task
    cannot report which half failed.

0.3 **Idempotence never comes from a conditional.** `when: not already_installed`
    is the anti-pattern; `state: present` / `creates:` is the answer. See §B7.

0.4 A role must not decide whether it applies. If `tasks/main.yml` opens by
    working out whether this host is in scope, that logic belongs in the playbook
    that includes it.

> Measuring 0.1 honestly needs a YAML walker, not `grep` — a `when:` has to be
> attributed to its own task's module to tell an action from an include. The
> `check-one-action.py` walker that gates this and the `one-action-per-task.md`
> standard that specifies it land with Revenant's first roles (see
> [`../README.md`](../README.md)); until then this section is the doctrine to
> write to.

### A. Input validation and preflight tasks *inside* the role

This is the highest-value section. Most role failures are bad input discovered
halfway through a run, leaving a half-configured host.

1. Does the role have `meta/argument_specs.yml` defining every variable it consumes —
   with `type`, `required`, `description`, and `choices` where applicable? This is the
   preferred mechanism; it validates before any task runs and self-documents.
2. Failing that (or in addition), does `tasks/main.yml` open with a preflight block —
   conventionally `tasks/preflight.yml`, tagged `always` — that asserts:
   - every required variable is defined and non-empty, with a `fail_msg` that names
     the variable and says what a valid value looks like
   - mutually exclusive options aren't both set
   - numeric/port/path values are in sensible ranges
3. Platform guard: does the role assert `ansible_facts['os_family']` /
   `distribution_major_version` is one it actually supports, and fail with a clear
   message otherwise? Cross-check against `platforms` in `meta/main.yml` — a role
   claiming EL9 support with no EL9 vars file is a `critical` finding.
4. Version guards: `min_ansible_version` set in `meta/main.yml` and honoured. Any
   dependency on a collection is declared in `meta/requirements.yml` or `galaxy.yml`.
5. Environmental preconditions checked before mutation, where the role depends on them:
   required commands present, target paths writable, disk space sufficient,
   required ports free, upstream endpoints reachable. Use `ansible.builtin.assert`,
   `stat`, `wait_for`, `command` + `failed_when`. Flag preconditions the role clearly
   *assumes* but never checks.
6. Does gathering facts actually happen? If `gather_facts: false` is set anywhere
   upstream and the role reads `ansible_facts`, that's a `critical` finding.

### B. Idempotence

7. Every `command`/`shell`/`raw` task has `creates:`, `removes:`, or an explicit
   `changed_when:`. A bare `shell` is a `major` finding.

   **A guarding `when:` does NOT satisfy this** — see §A0 below. Idempotence must
   come from the module (`creates:`/`removes:`/`state:`) or from an honest
   `changed_when:`, never from a conditional deciding whether to run at all.
8. Read-only commands have `changed_when: false`.
9. No `lineinfile`/`replace` used where a templated file would be deterministic —
   flag regex-based mutation of files the role itself owns.
10. Loops don't re-create resources each run (check `loop` bodies for the same issue
    as #7).

### C. Check mode and diff

11. Role completes under `--check` without erroring. Fact-gathering commands that
    must run in check mode carry `check_mode: false`; tasks that mutate do not.
12. Tasks handling secrets set `no_log: true` — and note where `no_log` would hide
    a genuinely needed diff.

### D. Failure behaviour

13. `ignore_errors: true` — every instance is a finding. Replace with a specific
    `failed_when:` expression or `block`/`rescue`.
14. Multi-step mutations that can leave a host half-configured are wrapped in
    `block`/`rescue`/`always`, with `always` doing cleanup (service restart, temp
    file removal, lockfile release).
15. Network-dependent tasks (package installs, downloads, API calls) have
    `retries`/`delay`/`until` rather than failing on a single blip.
16. Handlers: every `notify` names a handler that exists; handler names are stable;
    `meta: flush_handlers` is used where the role depends on a restart happening
    before a later task. Note that handlers don't fire on a failed run — flag any
    role whose correctness depends on that.

### E. Structure and correctness

17. FQCN used for all modules (`ansible.builtin.copy`, not `copy`). No deprecated
    modules or `with_*` loops where `loop` applies.
18. Variables are prefixed with the role name. Flag any generic name
    (`port`, `user`, `config_path`) that could collide across roles.
19. `defaults/main.yml` holds every user-overridable variable with a sane default;
    `vars/main.yml` holds only things users should not override. Flag inversions.
20. No hardcoded secrets, tokens, keys, or internal hostnames. Grep for high-entropy
    strings, `password:`, `token:`, `BEGIN PRIVATE KEY`. Report the location only —
    **never** print a discovered secret value into the report.
21. `delegate_to` / `run_once` / `serial` usage is correct and commented where subtle.
22. Tags are consistent across the role; preflight/assert tasks are tagged `always`
    so `--tags` runs don't skip validation.

### F. Testing and documentation

23. A Molecule scenario exists and covers: converge, **converge again and assert zero
    changes** (idempotence), and a `verify` stage that asserts observable end state
    (service running, port listening, file contents) rather than just re-asserting
    what the role set.
24. Test matrix covers every platform listed in `meta/main.yml`.
25. `README.md` documents every variable in `defaults/`, with type, default, and
    whether required — and matches `argument_specs.yml`. Divergence is a finding.
26. At least one realistic example playbook.
