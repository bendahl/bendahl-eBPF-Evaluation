# Aya Examples
This directory contains some example BPF programs written in Rust, using the [Aya](https://github.com/aya-rs/aya) library.
These implementations served the purpose of evaluating Aya.
If you would like to test the implementations yourself, you may use the predefined [Vagrant](https://www.vagrantup.com/) testenvironment, which also serves as a build environment.

##  Prerequisites
As outlined in the [main document](../README.md#prerequisites), all that is required to build and run the examples is virtualized test environment that can be spun up using Vagrant and Virtualbox.
Note that in order to run the loadbalancer example, three VMs are required, so you will need enough processing power on your machine to host these instances.

## Build
All builds use Rust's Cargo build tool under the hood.
To further simplify things, make is used to offer more convenient commands.
These are:

- `make`: Cleans and builds the project.
- `make build`: Perform a full build (user space program and BPF program).
- `make build-ebpf`: Build the BPF program.
- `make build-ebpf-release`: Perform a release build of the BPF program.
- `make clean`: Cleans up the current working tree.
- `make clean`: Cleans up the current working tree.
- `make testenvironment-up`: Provisions the test environment. 
- `make testenvironment-down`: Deletes and removes all files of the test environment.
- `make vmlinux`: Generate kernel data structure interfaces.

**Note that a simple `make` is typically sufficient to cleanly build the project.**

## Testing
Once the virtualized environment is up and running, you may enter a shell using the command `vagrant ssh`.
The directory `/vagrant` is a shared directory that allows read and write access to the project directory.
Test runs can be executed directly from within this directory.
**The final binaries are located in `./target/debug/[program_name]` for debug builds and `./target/release/[program_name]` for release builds.**
Also, the user `vagrant` does have sudo and does not require a password to execute a command via `sudo`.

## Development
As mentioned above, the test environment also contains a pre-configured toolchain to build the example programs. 
You can run builds from within the `/vagrant` directory.
There is one downside to this approach, however: The shared directory is not optimized for performance, so builds will take significantly longer to complete than on the host.

 