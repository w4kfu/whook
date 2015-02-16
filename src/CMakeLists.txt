set(WHOOK_FILES_SRC
    info.cpp
    #main.cpp
    memory.cpp
    modules.cpp
    pestuff.cpp
    process.cpp
    threads.cpp
    utils.cpp
    network.cpp
    file.cpp
    dump.cpp)

include_directories(${CMAKE_SOURCE_DIR}/src/include/)    
    
add_library(whook ${WHOOK_FILES_SRC})