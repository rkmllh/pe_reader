cmake_minimum_required(VERSION 3.10)

project(PeReader C)

set(SOURCES
    source.c
    Image.h
    mem.c
    mem.h
)

add_executable(pe_reader ${SOURCES})
