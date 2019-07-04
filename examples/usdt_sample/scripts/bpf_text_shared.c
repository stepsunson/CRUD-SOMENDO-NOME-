#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

/**
 * @brief Helper method to filter based on the specified inputString.
 * @param inputString The operation input string to check against the filter.
 * @return True if the specified inputString starts with the hard-coded filter string; otherwise, false.
 */
static inline bool filter(char const* inputString)
{
    static const char* null_ptr = 0x0;
    static const char null_terminator = '\0';

    static const char filter_string[] = "FI