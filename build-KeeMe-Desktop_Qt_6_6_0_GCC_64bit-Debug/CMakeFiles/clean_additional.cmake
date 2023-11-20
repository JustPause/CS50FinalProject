# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/KeeMe_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/KeeMe_autogen.dir/ParseCache.txt"
  "KeeMe_autogen"
  )
endif()
