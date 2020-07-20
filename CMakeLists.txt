cmake_minimum_required (VERSION 3.0)

project(weizz C)

add_compile_options(-g -O0)
#add_compile_options(-flto -O3)

set(SOURCES
  src/bitmap.c
  src/extras.c
  src/fuzz_one.c
  src/get_deps.c
  src/globals.c
  src/init.c
  src/main.c
  src/queue.c
  src/run.c
  src/signals.c
  src/stats.c
  src/tags.c
  src/utils.c
  src/pre_fuzz.c
  src/checksums.c
)

add_executable(weizz ${SOURCES})

target_include_directories(weizz PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(weizz dl)

add_executable(weizz-showmap utils/weizz-showmap.c)

target_include_directories(weizz-showmap PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(weizz-showmap dl)
