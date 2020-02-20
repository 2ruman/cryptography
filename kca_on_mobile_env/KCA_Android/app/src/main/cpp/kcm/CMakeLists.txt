
cmake_minimum_required( VERSION 3.4.1 )

set( MTAG "TRUMAN :: ")

message( ${MTAG} "Start building KCM...!!!" )

SET ( CMAKE_VERBOSE_MAKEFILE true )

set( SRC_FILES
        src/sha256.c )

add_library(
        kcm
        SHARED
        ${SRC_FILES} )

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/include )

find_library(
        log-lib
        log)

target_link_libraries(
        kcm
        ${log-lib} )