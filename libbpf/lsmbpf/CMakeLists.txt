cmake_minimum_required(VERSION 3.18)
project(lsmbpf)

include(ExternalProject)

set(CMAKE_CXX_STANDARD 17)

add_executable(lsmbpf lsmbpf.cpp)
set(LIBBPF_SUBDIR ${CMAKE_CURRENT_BINARY_DIR}/_deps/libbpf)
target_link_libraries(lsmbpf -static ${LIBBPF_SUBDIR}/usr/lib64/libbpf.a elf z)

# Add libbpf as an external dependency
# Note that libbpf does use make instead of CMAKE, which is why it is added as an external project.
# This gives us more control over things like build commands, etc...
ExternalProject_Add(libbpf
        DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
        GIT_REPOSITORY https://github.com/libbpf/libbpf.git
        GIT_TAG v1.2.0
        SOURCE_DIR ${libbpf_SOURCE_DIR}
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make -C src/
        INSTALL_COMMAND BUILD_STATIC_ONLY=y DESTDIR=${LIBBPF_SUBDIR} make -C src/ install
        )
add_library(libbpf_libbpf STATIC IMPORTED GLOBAL)

add_dependencies(lsmbpf libbpf skeletons)
include_directories(BEFORE SYSTEM ${LIBBPF_SUBDIR}/usr/include)


add_custom_target(vmlinux ALL
        COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${PROJECT_SOURCE_DIR}/vmlinux.h
)

# Build bpf code and create object file
add_custom_target(bpf ALL 
        COMMAND clang -g -O2 -c -target bpf -o ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}.bpf.o ${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}.bpf.c
        DEPENDS vmlinux
)

add_custom_target(skeletons ALL
        COMMAND bpftool gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}.bpf.o > ${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}.skel.h
        DEPENDS bpf
)

