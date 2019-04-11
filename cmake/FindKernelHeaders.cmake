# Find the kernel headers for the running kernel release
# This is used to find a "linux/version.h" matching the running kernel.

execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(KERNELHEADERS_DIR
        include/linux/user.h
        PATHS
        # RedHat derivatives
        /usr/src/kernels/${KERNEL_RELEASE}
        # Debian derivatives
        /usr/src/linux-headers-${KERNEL_RELEASE}
        )

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")

if (KERNELHEADERS_DIR)
    set(KERNELHEADERS_INCLUDE_DIRS
    