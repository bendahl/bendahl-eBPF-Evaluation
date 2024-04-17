# This script calculates three key metrics regarding issues (tickets):
# - tickets opened 
# - tickets closed
# - mean age of closed tickets

import statistics
from datetime import datetime, timezone
from github import Auth
from github import Github

# list of repositories to query
repos = ["aya-rs/aya", "cilium/ebpf", "libbpf/libbpf",
         "aquasecurity/libbpfgo", "libbpf/libbpf-rs",
         "foniod/redbpf"]
# autenticate with temporary token and initialize API object
auth = Auth.Token("")
g = Github(auth=auth)

# iterate over repositories (r represents a single repository)
for r in repos:
    # obtain repository object
    repo = g.get_repo(r)

    # set timerange as specified in paper
    start_date = datetime(2022, 12, 1, tzinfo=timezone.utc)
    cutoff_date = datetime(2023, 6, 5, tzinfo=timezone.utc)

    open_issues = []
    for issue in repo.get_issues(state='open', since=start_date):
        if issue.created_at <= cutoff_date:
            open_issues.append(issue)

    closed_issues = []
    for issue in repo.get_issues(state='closed', since=start_date):
        if issue.created_at <= cutoff_date:
            closed_issues.append(issue)
    sum_opened_issues = len(closed_issues) + len(open_issues)

    # ensure that closed_issues is set to a value that is not None
    # in order to prevent exceptions
    closed_issues = closed_issues or [0]
    # build a list of ages of all closed tickets
    closed_ticket_ages = [(issue.closed_at - issue.created_at).days
                          for issue in closed_issues]
    print(
        f"{r}: opened={sum_opened_issues}; closed={len(closed_issues)}; "
        f"closed (%): {len(closed_issues) * 100 // sum_opened_issues}; "
        f"mean_age_days={int(statistics.mean(closed_ticket_ages))}")

g.close()

# OUTPUT:
#
# aya-rs/aya: opened=286; closed=247; closed (%): 86; mean_age_days=74
# cilium/ebpf: opened=179; closed=160; closed (%): 89; mean_age_days=31
# libbpf/libbpf: opened=85; closed=83; closed (%): 97; mean_age_days=93
# aquasecurity/libbpfgo: opened=124; closed=101; closed (%): 81; mean_age_days=83
# libbpf/libbpf-rs: opened=196; closed=189; closed (%): 96; mean_age_days=22
# foniod/redbpf: opened=22; closed=8; closed (%): 36; mean_age_days=7
