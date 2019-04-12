# - Try to find liblzma
# Once done this will define
#
#  LIBLZMA_FOUND - system has liblzma
#  LIBLZMA_INCLUDE_DIRS - the liblzma include directory
#  LIBLZMA_LIBRARIES - Link these to use liblzma

if (LIBLZMA_LIBRARIES AND LIBLZMA_INCLUDE_DIRS)
    set (LibLzma_FIND_QUIETLY TRUE)
endif (LIBLZMA_LIBRARIES AND LIBLZMA_INCLUDE_DIRS)

find_path (LIBLZMA_INCLUDE_DIRS
  NAMES
    lzma.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)