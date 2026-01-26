cmake_minimum_required(VERSION 3.10)

project(X86DisassemblyEngine VERSION 1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Disable MSVC specific warnings
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# Source files
set(SOURCES
    "反汇编引擎.c"
    "disasm.c"
    "PETools.c"
)

# Header files
set(HEADERS
    "disasm.h"
    "PETools.h"
)

# Add the executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Organize files into folders for IDEs (like Visual Studio)
source_group("Source Files" FILES ${SOURCES})
source_group("Header Files" FILES ${HEADERS})
