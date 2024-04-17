# This script determines the average number of files in a commit within the given commit range for each framework 
#
# Note that in order to successfully run this script you will need a recent version of git
# see this issue for details: https://github.com/ishepard/pydriller/issues/271
import os.path
from pydriller.metrics.process.change_set import ChangeSet

frameworks = {"aya": ("15be301f8c1c57df3b94a79bdb808cb9135013c8", "d85b36f6d80236f142395f1ab173acbed74af99b"),
              "ebpf": ("ac675eba74ca67b6e876e658f8714a3f6b2bf5c5", "3cd2cb36d0786219e49e7dde9c2debfdc7c304ca"),
              "libbpf": ("66684189f0f5d182b1c3ab362fc0f919970c7079", "fbd60dbff51c870f5e80a17c4f2fd639eb80af90"),
              "libbpfgo": ("54b9c393a554215fc7ead0165aa6a1ce46eed0ed", "1be18b35389c51e6934472218fd01572324eebda"),
              "libbpf-rs": ("b279c47cb5752e05e97bae433b4ceb0cba6ed59d", "8f6a1e9b3b2c2c9c668674d5ec6523cbb98179e1"),
              "redbpf": ("85e6ed35d4a0fd04b4dacde544c7f9e7c5bc93b8", "845fffa242d2b31a75fc61d251b43805ddf87c6f")}

# iterate over framework and commit range
for f, commit in frameworks.items():
    repo_path = os.path.join("~/rd/bpf", f)
    # unpack commit tuple
    from_commit, to_commit = commit
    metric = ChangeSet(path_to_repo=repo_path,
                       from_commit=from_commit,
                       to_commit=to_commit)
    maximum = metric.max()
    average = metric.avg()
    print(f"{f}: average no. files = {metric.avg()}")
