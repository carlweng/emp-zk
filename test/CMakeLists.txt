function(add_test_case folder name)
    set(target test_${folder}_${name})
    add_executable(${target} ${folder}/${name}.cpp)
    target_link_libraries(${target} PRIVATE emp-zk::emp-zk)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${folder}_${name}
             COMMAND ${target}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

function(add_test_case_with_run folder name)
    set(target test_${folder}_${name})
    add_executable(${target} ${folder}/${name}.cpp)
    target_link_libraries(${target} PRIVATE emp-zk::emp-zk)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${folder}_${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:${target}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

# Boolean ZK
add_test_case_with_run(bool example)
add_test_case_with_run(bool bool_io)
add_test_case_with_run(bool memory_scalability)
add_test_case_with_run(bool input_scalability)
add_test_case_with_run(bool circuit_scalability)
add_test_case_with_run(bool sha256)
add_test_case_with_run(bool polynomial)
add_test_case_with_run(bool inner_prdt)

# Arithmetic ZK
add_test_case_with_run(arith abconversion)
# Edabit setup is fixed-cost (~10 min release / ~hours debug); skip in
# fast CI via `ctest -LE slow`.
set_tests_properties(arith_abconversion PROPERTIES LABELS slow)
add_test_case_with_run(arith zk_proof)
add_test_case_with_run(arith ostriple)
add_test_case_with_run(arith input_scalability)
add_test_case_with_run(arith circuit_scalability)
add_test_case_with_run(arith polynomial)
add_test_case_with_run(arith inner_prdt)
add_test_case_with_run(arith matrix_mul)
add_test_case_with_run(arith sis)

# VOLE
add_test_case_with_run(vole vole_triple)
add_test_case_with_run(vole base_svole)
add_test_case_with_run(vole lpn)

# RAM ZK
add_test_case_with_run(ram-zk ram_test)
add_test_case_with_run(ram-zk ram_ext_test)
add_test_case_with_run(ram-zk ro_ram_test)
