# `results/` — the only run output that ships

Normalized baseline results, one directory per `<baseline>/<batch>/`:

```
results/
  <baseline>/
    <batch>/                 e.g. b1-gpt4o, b2-sonnet5
      results.json           array of records matching ../../schema/baseline_result.schema.json
      patches/<case_id>.diff the produced patches, one per case
      manifest.json          commit run, model, budget, date, host, who ran it
  index.json                 batch registry (append-only)
```

Raw tool output, container state and logs stay in `../work/` (gitignored). If something in
`work/` matters, it belongs in a record here or in the baseline's `notes.md` — not committed raw.

A record is publishable only when it carries `baseline_commit`, `model`, and `budget`. Without
those three, the number cannot be compared to anything, including a later run of the same tool.
