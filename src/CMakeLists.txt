cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_COMPILER "/usr/bin/clang++" CACHE STRING "clang++ compiler" FORCE)

set(CMAKE_CXX_FLAGS_ORIGIN "-std=c++14 -O2 -Wall -DDEBUG -Wno-unused-function -Wno-unused-label")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_ORIGIN}")

get_filename_component(INCLUDE_DIR ../include ABSOLUTE)
include_directories("${INCLUDE_DIR}")

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

find_program(PROTOC NAMES protoc)
find_package(PkgConfig)

###############################
#     Compile proto
###############################

# grpcのファイル生成
# *.pb.cc
# *.pb.h

if(PKG_CONFIG_FOUND)
    pkg_check_modules(PROTOBUF REQUIRED
        protobuf
        )
    pkg_check_modules(GRPC REQUIRED
        grpc++
        )
endif()

set(protobuf_MODULE_COMPATIBLE TRUE)

find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)

find_package(Protobuf REQUIRED)

get_filename_component(XNAT_PROTO xnat.proto ABSOLUTE)
get_filename_component(XNAT_PROTO_PATH "${XNAT_PROTO}" PATH)

protobuf_generate_cpp(XNAT_PROTO_SRC XNAT_PROTO_HDR "${XNAT_PROTO}")

set(XNAT_GRPC_SRC "${CMAKE_CURRENT_BINARY_DIR}/xnat.grpc.pb.cc")
set(XNAT_GRPC_HDR "${CMAKE_CURRENT_BINARY_DIR}/xnat.grpc.pb.h")

add_custom_command(
    OUTPUT "${XNAT_GRPC_SRC}" "${XNAT_GRPC_HDR}"
    COMMAND protoc
    ARGS --grpc_out="${CMAKE_CURRENT_BINARY_DIR}" -I "${XNAT_PROTO_PATH}"
    --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN}" "${XNAT_PROTO}"
    DEPENDS "${XNAT_PROTO}")


add_library(xnat_grpc STATIC ${XNAT_PROTO_SRC} ${XNAT_GRPC_SRC})

###############################
#     Compile xnat_dump
###############################
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PROTOBUF_CFLAGS} ${GRPC_CFLAGS}")

add_executable(xnat_dump xnat_dump.cc)

target_link_libraries(xnat_dump
    ${PROTOBUF_LIBRARIES}
    ${GRPC_LIBRARIES}
    xnat_grpc
    bpf
    pcap
    )

###############################
#     Compile controller
###############################
add_executable(controller controller.cc)

target_link_libraries(controller
    ${PROTOBUF_LIBRARIES}
    ${GRPC_LIBRARIES}
    xnat_grpc
    bpf
    )

###############################
#     Compile xnat_stats
###############################
add_executable(xnat_stats
    xnat_stats.cc
    # ${XNAT_GRPC_SRC}
    # ${XNAT_PROTO_SRC}
    )

target_link_libraries(xnat_stats
    # ${PROTOBUF_LIBRARIES}
    # ${GRPC_LIBRARIES}
    bpf
    )



###############################
#     Compile xnat
###############################
if(PKG_CONFIG_FOUND)
    pkg_check_modules(NETLINK REQUIRED
        libnl-3.0
        libnl-route-3.0
        )
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NETLINK_CFLAGS}")

add_executable(xnat xnat.cc)

target_link_libraries(xnat
    ${PROTOBUF_LIBRARIES}
    ${GRPC_LIBRARIES}
    ${NETLINK_LIBRARIES}
    xnat_grpc
    bpf
    )

INSTALL(TARGETS xnat_dump RUNTIME DESTINATION ${INSTALL_PATH})
INSTALL(TARGETS xnat_stats RUNTIME DESTINATION ${INSTALL_PATH})
INSTALL(TARGETS xnat RUNTIME DESTINATION ${INSTALL_PATH})
INSTALL(TARGETS controller RUNTIME DESTINATION ${INSTALL_PATH})
