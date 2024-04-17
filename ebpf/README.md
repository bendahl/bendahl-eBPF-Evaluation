# eBPF Examples
This directory contains some example BPF programs written in Go and C, using the [eBPF](https://github.com/cilium/ebpf) library.
These implementations served the purpose of evaluating eBPF.

##  Prerequisites
As outlined in the [main document](../README.md#prerequisites), all that is required to build and run the examples is virtualized test environment that can be spun up using Vagrant and Virtualbox.
Note that in order to run the load balancer example, three VMs are required, so you will need enough processing power on your machine to host these instances.

## Build
The user space Go programs are built using the `go` tool. 
It defines a set of targets that can be used to build the various parts of each example.
These are:

- `make`: Cleans and builds the project.
- `make bpfgen`: Generates Go interface types.
- `make build`: Runs the Go build. **Note that this will not automatically perform the code generation step.**
- `make clean`: Cleans up the current working tree.
- `make testenvironment-up`: Provisions the test environment. 
- `make testenvironment-down`: Deletes and removes all files of the test environment.
- `make vmlinux`: Creates the required vmlinux.h header file.

**Note that it is sufficient to run `make` in most cases, as this executes all required build steps.**

## Testing
Once the virtualized environment is up and running, you may enter a shell using the command `vagrant ssh`.
The directory `/vagrant` is a shared directory that allows read and write access to the project directory.
Test runs can be executed directly from within this directory.
Also, the user `vagrant` does have sudo and does not require a password to execute a command via `sudo`.

## Development
As mentioned above, the test environment also contains a pre-configured toolchain to build the example programs. 
You can run builds from within the `/vagrant` directory.
There is one downside to this approach, however: The shared directory is not optimized for performance, so builds will take significantly longer to complete than on the host.

 