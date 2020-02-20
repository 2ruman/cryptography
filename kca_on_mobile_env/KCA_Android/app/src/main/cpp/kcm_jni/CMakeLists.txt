
cmake_minimum_required( VERSION 3.4.1 )

set( MTAG "TRUMAN :: ")

message( ${MTAG} "Start building KCM_JNI...!!!" )

set( CMAKE_VERBOSE_MAKEFILE true )

set( SRC_FILES
        src/sha256_jni.c )

####################################################################################################

set( SUB_LIB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../kcm )
set( SUB_LIB_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../kcm/build/${ANDROID_ABI}/outputs )
file( MAKE_DIRECTORY ${SUB_LIB_BUILD_DIR} )

message( ${MTAG} "Add sub-library..." )
message( ${MTAG} "Current source directory : " ${CMAKE_CURRENT_SOURCE_DIR} )
message( ${MTAG} "Sub-library source path  : " ${SUB_LIB_SRC_DIR} )
message( ${MTAG} "Sub-library build path   : " ${SUB_LIB_BUILD_DIR} )
message( ${MTAG} "Library output path      : " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} )

add_subdirectory(
        ${SUB_LIB_SRC_DIR}
        ${SUB_LIB_BUILD_DIR} )

add_library(
        kcm-imported
        SHARED
        IMPORTED )

set_target_properties(
        kcm-imported
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libkcm.so )

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../kcm/include )

###################################################################################################

message( ${MTAG} "Add library..." )
message( ${MTAG} "Source files : " ${SRC_FILES} )

add_library(
        kcm-jni
        SHARED
        ${SRC_FILES} )

find_library(
        log-lib
        log )

target_link_libraries(
        kcm-jni
        kcm-imported
        ${log-lib} )