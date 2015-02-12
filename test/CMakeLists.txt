include_directories(${CMAKE_SOURCE_DIR}/src/include/)  

set(FILES_TEST_SRC whook_test.cpp)

add_executable(whook_test ${FILES_TEST_SRC})

target_link_libraries(whook_test whook ${LINK_LIBS})