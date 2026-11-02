# Target Update

A dependency-free, responsive sales workspace with a Python API. The local
prototype persists to SQLite. The same API can use a private Supabase state store
on Vercel; Supabase and Vercel deployment have not been tested or provisioned here.

## Run locally

Requires Python 3.12+. No package installation or build step is needed.

```bash
cd /workspace/target-update
read -rsp 'Initial admin PIN: ' TARGET_ADMIN_PIN; echo
export TARGET_ADMIN_PIN
export TARGET_SUBNO_HMAC_KEY='replace-with-a-long-random-private-secret'
python3 api/index.py
```

The local server listens on port 3000 (override with `PORT`). It creates
`.data/target.db` on first sign-in. Set the owner's requested initial PIN at the
prompt. Owner username: **B000884**. No email is needed. The initial PIN must be
changed at first sign-in. After initialization, the stored hash is authoritative;
changing the bootstrap environment variable does not reset the account.

Use the existing checkout. Each cloud task is isolated; do not create worktrees
unless explicitly requested. Stop and restart processes as needed; processes do
not survive an environment snapshot. Preserve `.data` to retain local changes.

## Workflow

1. Sign in as the owner and change the initial PIN.
2. In **Team members**, review the Excel roster, set unique initial PINs, and
   activate each account. Agents must change their initial PIN on first sign-in.
3. Select a reporting month and set targets. Workbook values are offered as a
   template, never silently assigned to a month. Alternatively, in **Upload
   reports**, upload the monthly XLSX target workbook, review the preview, and
   confirm the import. The sheet must match the reporting month (e.g. NOV).
   POST and BB map directly, and BH + Expats maps to MUL; Insurance is ignored.
   Unknown TABS IDs block the import until the employees are added. Only listed
   employees' targets for the selected month are replaced. Owner/leader
   aggregate targets are excluded from the team total.
4. Upload the four supplied CSV report types in **Upload reports**. Import dates
   determine their month. Empty files with valid headers are supported.
5. Inspect the import review for missing rules, unknown IDs, or malformed rows.
   Add unknown agents before uploading the same report again.
6. Add confirmed Migration, Upgrade, and Locking rules in **Campaign rules**.
   Saving or archiving a rule recalculates existing transactions.

### Confirmed business rules

- Only `tag_pay_desk` / `tag_paydesk` equal to **Telesales** count, ignoring case
  and surrounding spaces. Agent matching uses `tag_agent_id`, not the operator ID.
- Sales: Postpaid Voice/Signature and Family → POST; MBB/Fiber/5G → BB.
- Active supplied campaign rules match normalized segment, rental **including
  VAT** (to three decimal places), and transaction date. The latest applicable
  effective date wins. Archived rules do not score transactions.
- Agents see Migration + Upgrade + Locking as **MUL**. Leader views show Migration
  and Upgrade + Locking separately. Agents and leaders can read only their own
  results. Only B000884 can read all results or change reports/accounts/rules/targets.
- Only one Telesales transaction is kept for each SUBNO across report types and
  repeated uploads. Earliest transaction date wins; on the same date,
  Migration/Upgrade takes priority over Locking. Other same-date ties retain
  the existing record. General corrections/reversals are not supported.
- Run rate uses elapsed calendar days in Bahrain time and actual month length.
- Unknown IDs are rejected with a review entry. Missing scoring rules produce
  pending transactions, excluded from points until a confirmed rule is added.

### Still awaiting business definitions

- Migration/Upgrade/Locking points and any eligibility conditions were not given.
  No default points are assigned. The rule editor currently supports a flat
  per-transaction rule for each of these activities; complex campaign conditions
  need a further implementation once specified.
- Family-change reports map to POST, but `TO_RENTAL` is not explicitly documented
  as VAT-inclusive. These rows remain unscored until the rental mapping is
  confirmed and implemented. The supplied family-change report is header-only.
- The UI archives rather than permanently deletes campaign rules so they can be
  restored. It does not provide import reversal or hard deletion of accounts.

## Security

Access is enforced in the API, not just hidden in the UI. Agent requests return
only their own dashboard; they receive no team roster, imports, rules, or audit
logs. Customer numbers and contract identifiers are used to fingerprint rows in
memory; stored transactions contain a SHA-256 row fingerprint and keyed
HMAC-SHA256 SUBNO matching key, agent, date, category, rental and score, with
no raw subscriber numbers. Keep TARGET_SUBNO_HMAC_KEY secret and stable.
Rotating it requires re-keying existing transaction match keys.

PINs use salted scrypt hashes. Eight-hour opaque sessions are stored as hashes
and sent via HttpOnly/SameSite=Strict cookies (Secure on Vercel). Five failed
attempts lock an ID for fifteen minutes. Initial PIN changes are mandatory,
PIN resets invalidate existing sessions, and cross-origin writes are rejected.
For a public production rollout, add edge-level rate limits and monitoring;
short numeric PINs have inherently limited entropy.

The Supabase table has RLS enabled with **no client policies**. Anon and
authenticated roles cannot call its storage RPCs or read it. Only the server's
service-role key can access it. All user authorization happens in the Python API.
The JSON state store is appropriate for a small prototype, not large-scale
analytics: move to normalized tables and granular database authorization as the
product grows. Concurrent writes use revision checks and retry on conflict.

## Deploy to Supabase + Vercel

1. Use the `7ussain3lii/target-update` GitHub repository. The checkout began
   unborn and the remote had no refs. Never reset or overwrite later remote work.
2. Run `supabase/migrations/001_target_update.sql` in a Supabase project's SQL editor.
3. Import the GitHub repository into Vercel. Choose **Other** as the framework;
   public static files and `api/index.py` are used. No frontend build is required.
4. Configure these **server-only** environment variables through Vercel settings:
   `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `TARGET_ADMIN_PIN` (initialization
   only), and `TARGET_SUBNO_HMAC_KEY` (long, random and stable).
   Never prefix secret keys with `PUBLIC_` or expose them to JavaScript.
5. Deploy, sign in, replace the initial PIN, then activate accounts, set targets,
   and upload reports. Local SQLite data is not automatically migrated.
6. Verify real remote persistence across deployment/restarts and the access tests
   before inviting agents. This remote deployment has not yet been performed.

No credentials are committed. Local storage is intentionally disabled when
`VERCEL` is set without Supabase to prevent ephemeral data loss. This workspace's
restricted command sandbox cannot open sockets; GitHub, Supabase, Vercel and Documents
connectors are unavailable. GitHub HTTPS access works when commands run outside
the socket-restricted sandbox. Supabase and Vercel have no configured credentials.
A published website cannot be claimed until deployment is verified.

## Validate

```bash
python3 -m unittest discover -s tests -v
node --check public/app.js
```

The suite exercises actual HTTP login, PIN change, agent isolation, denied agent
writes, logout, throttling, cross-origin rejection, scoring, duplicate imports,
pending transactions, effective dates, month-specific targets, and atomic local
persistence. An additional original-workspace check reads the supplied reports;
it is explicitly skipped when those attachments are unavailable.
