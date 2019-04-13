# Locate Lua library
# This module defines
#  LUAJIT_FOUND, if false, do not try to link to Lua
#  LUAJIT_LIBRARIES
#  LUAJIT_INCLUDE_DIR, where to find lua.h
#
# Note that the expected include convention is
#  #include "lua.h"
# and not
#  #include <lua/lua.h>
# This is because, the lua location is not standardized and may exist
# in locations other than lua/

#=============================================================================
# Copyright 2007-2009 Kitware, Inc.
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distributed this file outside of CMake, substitute the full
#  License text for the above reference.)
#
# ################
# 2010 - modified for cronkite to find luajit instead of lua, as it was before.
#

FIND_PATH(LUAJIT_INCLUDE_DIR lua.h
  HINTS
  $ENV{LUAJIT_DIR}
  PATH_SUFFIXES luajit-2.0 luajit2.0 luajit luajit-2.1
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw # Fink
  /opt/local # DarwinPorts
  /opt/csw # Blastwave
  /opt
)

FIND_LIBRARY(LUAJIT_LIBRARY
  NAMES libluajit-51.a libluajit-5.1.a libluajit.a libluajit-5.1.so
  HINTS
  $ENV{LUAJIT_DIR}
  PATH_SUFFIXES lib64 lib
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw
  /opt/lo