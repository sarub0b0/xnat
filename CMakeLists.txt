cmake_minimum_required(VERSION 3.5)

project(xnat CXX)

get_filename_component(INSTALL_PATH bin ABSOLUTE)

add_subdirectory(src)
