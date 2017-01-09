# Open Ssh skills

Agent skills for the `open-ssh` CLI. Run the checks from the repository root:

```bash
pnpm run build:ts
pnpm run check:skills
```

`check-skills.ts` validates frontmatter, the `## Safety` section, that every
referenced command and flag exists in `--help`, that mutating commands document
a `--dry-run` invocation, and that the package license stays `Apache-2.0`.
