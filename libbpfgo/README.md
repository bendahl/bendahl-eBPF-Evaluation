# Libbpfgo Examples
This directory contains some example BPF programs written in Go and C, using the [Libbpfgo](https://github.com/aquasecurity/libbpfgo) library.
These implementations served the purpose of evaluating Libbpfgo.

##  Prerequisites
As outlined in the [main document](../README.md#prerequisites), all that is required to build and run the examples is virtualized test environment that can be spun up using Vagrant and Virtualbox.
Note that in order to run the load balancer example, three VMs are required, so you will need enough processing power on your machine to host these instances.

## Build
The user space Go programs are built using the `go` tool. 
To build the kernel space BPF program, clang is used.
In order to simplify the build, `make` is leveraged to unify the build.
Note, however, that due to the fact that Libbpfgo requires a suitable version of Libbpf to be present, this dependency (along with Libbpfgo) is vendored.
This, in turn, means that Libbpfgo has to be built locally as well. 
The makefile included in each project ensures that this prerequisite is met.
It defines a set of targets that can be used to build the various parts of each example.
These are:

- `make`: Cleans and builds the project.
- `make clean`: Cleans up the current working tree.
- `make [program]`: Builds the [program] (for example, the "packetfilter") and all its dependencies. The binary is placed in the current working directory.
- `make [program].bpf.o`: Builds the BPF program.
- `make libbpfgo`: Builds the vendored Libbpfgo version.
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

 