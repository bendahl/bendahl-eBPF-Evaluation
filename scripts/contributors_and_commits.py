# This script determines the number of contributors and commits in the given time range (see settings below).
#
# Note that in order to successfully run this script you will need a recent version of git
# see this issue for details: https://github.com/ishepard/pydriller/issues/271
import os.path
from datetime import datetime, timezone

from pydriller import Repository

repos = ["aya", "ebpf", "libbpf",
         "libbpfgo", "libbpf-rs",
         "redbpf"]

# only consider the given timerange for the analysis
start_date = datetime(2022, 12, 1, tzinfo=timezone.utc)
cutoff_date = datetime(2023, 6, 5, tzinfo=timezone.utc)
# iterate over framework and commit range
for r in repos:
    repo_path = os.path.join("~/rd/bpf", r)
    number_commits = 0
    # use set to get a list of unique contributors
    contributors = set()
    for commit in Repository(path_to_repo=repo_path,
                             since=start_date,
                             to=cutoff_date).traverse_commits():
        number_commits += 1
        contributors.add(commit.committer.email)

    print(f"{r}: no. commits = {number_commits}; contributors = {len(contributors)}")

# Output:
#
# aya: no. commits = 241; contributors = 27
# ebpf: no. commits = 144; contributors = 4
# libbpf: no. commits = 200; contributors = 4
# libbpfgo: no. commits = 49; contributors = 3
# libbpf-rs: no. commits = 231; contributors = 5
# redbpf: no. commits = 5; contributors = 2
