# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | 60 | 54 | 1 | 5 |
| file_log.csv | 35 | 30 | 1 | 4 |

- SHA-256 check outcome and what it establishes: Both CSV hashes match `evidence_manifest.json`. This shows the files are unchanged from the supplied baseline. It does not prove where the logs came from or that they are complete.
- One rejected event ID and the exact rejection reason: `auth_log.csv` A904 (CSV row 36) is a SUCCESS with an empty session_id. The audit reason is “successful login needs session_id”
- Number of flagged successful sessions: 3

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | none | 0 | 0 |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 | 2026-10-20T08:58:00Z | 08:58:00Z | FAIL, analyst01, 203.0.113.44, DF-PORTAL01 |
| auth_log.csv A003 | 2026-10-20T09:00:00Z | 09:00:00Z | FAIL, same account/IP/host (duplicate copy removed) |
| auth_log.csv A004 | 2026-10-20T10:01:00+01:00 | 09:01:00Z | FAIL, same account/IP/host |
| auth_log.csv A005 | 2026-10-20T09:03:00Z | 09:03:00Z | SUCCESS, session S-104 |
| file_log.csv F001 | 2026-10-20T09:05:00Z | 09:05:00Z | DOWNLOAD SUCCESS, S-104, 5242880 bytes |
| file_log.csv F002 | 2026-10-20T10:07:00+01:00 | 09:07:00Z | DOWNLOAD SUCCESS, S-104, 262144 bytes |
| file_log.csv F003 | 2026-10-20T09:13:00Z | 09:13:00Z | DOWNLOAD SUCCESS, S-104, 4096 bytes |

- Manual sum of download bytes, showing the addition: 5242880 + 262144 + 4096 = 5509120, matching summary.json.
- A001 versus A002: which qualifies for the A005 window and why? A002 (08:58:00Z) is exactly 5 minutes before A005 (09:03:00Z); the lower bound is inclusive, so it counts. A001 (08:57:59Z) is one second earlier and falls outside.
- F003 versus F004: which qualifies for the A005 follow-up and why? F003 (09:13:00Z) is exactly T + 10 minutes; the window includes its end, so it counts. F004 (09:13:01Z) is one second later and is excluded.
- Why F005 is excluded even though the account matches: F005 is in session S-OTHER, not S-104. The join requires username AND host AND session_id.
- One +01:00 timestamp and its equivalent UTC time: auth_log.csv A004 2026-10-20T10:01:00+01:00 = 2026-10-20T09:01:00Z.
- One limitation of excluding malformed records: F900, F901 and F902 are analyst01/S-104 downloads near A005 but were rejected (missing offset, bytes -1, bytes "unknown"), so the true volume for S-104 may be higher than recorded.

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

Run on 5 November 2026 in Windows PowerShell from the project folder:

```text
py check_solution.py               
test_supplied_case (__main__.CaseChecks.test_supplied_case) ... ok
test_closed_window_includes_zero_and_ten_minutes (__main__.DownloadChecks.test_closed_window_includes_zero_and_ten_minutes) ... ok
test_configurable_followup (__main__.DownloadChecks.test_configurable_followup) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks.test_does_not_mutate_either_input) ... ok
test_empty (__main__.DownloadChecks.test_empty) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks.test_keeps_alert_with_no_downloads) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks.test_ranking_event_ties_and_repeated_paths) ... ok
test_requires_session_account_host_action_and_success (__main__.DownloadChecks.test_requires_session_account_host_action_and_success) ... ok
test_conflicting_ids_are_not_silently_discarded (__main__.EvidenceChecks.test_conflicting_ids_are_not_silently_discarded) ... ok
test_equivalent_time_offsets_and_missing_offset (__main__.EvidenceChecks.test_equivalent_time_offsets_and_missing_offset) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks.test_hash_mismatch_stops_analysis) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks.test_supplied_quality_counts_and_duplicates) ... ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks.test_account_ip_and_host_must_all_match) ... ok
test_does_not_mutate_input (__main__.LoginChecks.test_does_not_mutate_input) ... ok
test_empty (__main__.LoginChecks.test_empty) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks.test_failures_without_success_are_not_alerts) ... ok
test_outside_equal_and_future_failures_do_not_count (__main__.LoginChecks.test_outside_equal_and_future_failures_do_not_count) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks.test_parameters_and_each_success_window) ... ok
test_ties_and_output_order (__main__.LoginChecks.test_ties_and_output_order) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks.test_unsorted_rows_and_evidence_order) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks.test_window_includes_exactly_five_minutes) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.009s

OK
```

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> Unsupported parts: The logs show activity by the account analyst01, not by an identified person, so "the attacker" is not established. A logged DOWNLOAD (F001-F003) records an application event; it does not prove theft, authorisation status, or that data left the system. Matching SHA-256 hashes only show the CSVs agree with the supplied manifest, not that the logs are authentic or complete; five auth and four file rows were also rejected.
>
> Rewrite: "Account analyst01 had three failed logins (A002-A004) before successful login A005, and session S-104 then recorded three successful downloads (F001-F003) totalling 5,509,120 bytes. These records justify further review but do not identify a person, show unauthorised access, or prove exfiltration."
>
> (GenAI tool: Claude, 5 Nov 2026)

One claim we corrected or independently verified, with event IDs:

We independently verified the S-104 byte total by locating auth_log.csv A005 and file_log.csv F001, F002 and F003 in the raw CSVs and adding the values ourselves: 5242880 + 262144 + 4096 = 5509120, which matches summary.json. We also confirmed that F002 (`2026-10-20T10:07:00+01:00`) equals 09:07:00 UTC and therefore falls inside the A005 follow-up window. We corrected the draft claim that "matching hashes prove the logs are authentic and complete": the hash match only shows agreement with the supplied manifest.

Final 180-220 word finding, reviewed and edited by the pair:

```
Observation: under the stated rule, three successful logins were flagged. The leading session is analyst01, session S-104 on DF-PORTAL01 from 203.0.113.44. Failures A002, A003 and A004 (08:58:00-09:01:00 UTC) preceded successful login A005 at 09:03:00 UTC. Between 09:05:00 and 09:13:00 UTC the portal recorded three successful downloads in that session (F001, F002, F003) totalling 5,509,120 bytes. By comparison, analyst02 session S-304 (success A018 at 10:05:00 UTC after failures A015-A017) recorded one download, F013, of 2,048 bytes, and backup_svc session S-204 (A014) recorded none. We prioritise S-104 because its recorded volume is far larger, not because it shows misuse. Limitations: the logs do not show who used the account, and clock accuracy and log completeness are unverified; the hash match only shows agreement with the supplied manifest. Also, three rejected S-104 rows (F900, F901, F902) were excluded, so the recorded total may be incomplete. Inference: a plausible benign explanation is that an authorised analyst mistyped a password and then downloaded case material for normal work. Next evidence requests: identity-provider and MFA records for A005, and proxy or firewall records showing whether and where F001-F003 were transferred.
```

## AI use and pair review

- Names of both partners: Poornima Pundir (completed individually, no partner)
- GenAI tool/ChatGPT date and displayed model: Claude (Anthropic), configured model claude-opus-5-5, used on 5 November 2026
- Prompts used and what they produced: Prompt 1 produced `find_login_sequences` with pseudocode and an explanation of the (username, source_ip, host) grouping key and both window boundaries. Prompt 2 produced `correlate_downloads` and explained why a username-only join is unsafe, the closed 10-minute window, and why zero-download alerts are kept. Prompt 3 produced the critique and two-sentence rewrite of the overstated claim above. Prompt 4 produced the draft finding, which was checked against the CSVs and summary.json before use. The debugging prompt was not needed.
- One follow-up question or correction, with a short response excerpt: Follow-up: "how does the code work?" Response excerpt: "The key line in find_login_sequences is the time-window filter: t - window <= r['timestamp'] < t. It keeps only failures from the five minutes before the successful login: a failure exactly five minutes earlier is included (<=), but one at the same second as the login is not (<)." I checked this against the data: A002 (08:58:00Z, exactly 5 minutes before A005) is counted, while A001 (08:57:59Z) is not.
- Results of code and evidence checks performed: `py check_solution.py LoginChecks` ran 9 tests, OK; `py check_solution.py DownloadChecks` ran 7 tests, OK; `py check_solution.py` ran 21 tests, OK. `py analyze_case.py` confirmed both SHA-256 hashes match the manifest and reported 3 flagged sessions. Manually traced A005/S-104 events in the raw CSVs, and my byte total of 5,509,120 matches `summary.json`.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
