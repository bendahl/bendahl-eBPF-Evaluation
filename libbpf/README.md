# Libbpf Examples
This directory contains some example BPF programs written in C++ and C, using the [Libbpf](https://github.com/libbpf/libbpf) library.
These implementations served the purpose of evaluating Libbpf.
Tjhe user space programs are written in C++ and the kernel space programs are written in C.

##  Prerequisites
As outlined in the [main document](../README.md#prerequisites), all that is required to build and run the examples is virtualized test environment that can be spun up using Vagrant and Virtualbox.
Note that in order to run the load balancer example, three VMs are required, so you will need enough processing power on your machine to host these instances.

## Build
All builds use the Clang build tool under the hood.
To further simplify things, make is used to offer more convenient commands.
These are:

- `make`: Cleans and builds the project.
- `make clean`: Cleans up the current working tree.
- `make build`: Builds all artifacts and place a copy of the final executable in your current working directory.
- `make testenvironment-up`: Provisions the test environment. 
- `make testenvironment-down`: Deletes and removes all files of the test environment.

## Testing
Once the virtualized environment is up and running, you may enter a shell using the command `vagrant ssh`.
The directory `/vagrant` is a shared directory that allows read and write access to the project directory.
Test runs can be executed directly from within this directory.
Also, the user `vagrant` does have sudo and does not require a password to execute a command via `sudo`.

## Development
As mentioned above, the test environment also contains a pre-configured toolchain to build the example programs. 
You can run builds from within the `/vagrant` directory.
There is one downside to this approach, however: The shared directory is not optimized for performance, so builds will take significantly longer to complete than on the host.

 