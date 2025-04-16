find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        "../src"
        /usr/local/include
)

link_directories(
        /usr/local/lib
)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread
)


option(NO_MPC_GG18 "NO_MPC_GG18" OFF)
option(NO_MPC_Li24 "NO_MPC_Li24" OFF)
option(NO_MPC_GG20 "NO_MPC_GG20" OFF)
option(NO_MPC_CMP "NO_MPC_CMP" OFF)
option(NO_TIME "NO_TIME" OFF)

if (${ENABLE_SNAP_SCOPE})
    set(NO_MPC_GG18 TRUE)
    set(NO_MPC_Li24 TRUE)
    set(NO_MPC_GG20 TRUE)
    set(NO_TIME TRUE)
endif()

if (NOT ${NO_MPC_Li24})
    # multi-thread
    add_executable(Li24.key_gen_mt_test Li24/key_gen_mt_test.cpp)
    add_test(NAME Li24.key_gen_mt_test COMMAND Li24.key_gen_mt_test)

    add_executable(Li24.sign_t_n_mt_test Li24/sign_t_n_mt_test.cpp)
    add_test(NAME Li24.sign_t_n_mt_test COMMAND Li24.sign_t_n_mt_test)

endif()

if (NOT ${NO_MPC_GG18})
    # gg18
    add_executable(gg18.key_gen_test gg18/key_gen_test.cpp CTimer.cpp)
    add_test(NAME gg18.key_gen_test COMMAND gg18.key_gen_test)

    add_executable(gg18.key_refresh_test gg18/key_refresh_test.cpp)
    add_test(NAME gg18.key_refresh_test COMMAND gg18.key_refresh_test)

    add_executable(gg18.sign_test gg18/sign_test.cpp)
    add_test(NAME gg18.sign_test COMMAND gg18.sign_test)

    # multi-thread
    add_executable(gg18.key_gen_mt_test gg18/key_gen_mt_test.cpp)
    add_test(NAME gg18.key_gen_mt_test COMMAND gg18.key_gen_mt_test)

    add_executable(gg18.sign_n_n_mt_test gg18/sign_n_n_mt_test.cpp)
    add_test(NAME gg18.sign_n_n_mt_test COMMAND gg18.sign_n_n_mt_test)

    add_executable(gg18.sign_t_n_mt_test gg18/sign_t_n_mt_test.cpp)
    add_test(NAME gg18.sign_t_n_mt_test COMMAND gg18.sign_t_n_mt_test)

    add_executable(gg18.key_refresh_mt_test gg18/key_refresh_mt_test.cpp)
    add_test(NAME gg18.key_refresh_mt_test COMMAND gg18.key_refresh_mt_test)
endif()

if (NOT ${NO_MPC_GG20})
    # gg20
    add_executable(gg20.sign_test gg20/sign_test.cpp)
    add_test(NAME gg20.sign_test COMMAND gg20.sign_test)
    # multi-thread
    add_executable(gg20.sign_n_n_mt_test gg20/sign_n_n_mt_test.cpp)
    add_test(NAME gg20.sign_n_n_mt_test COMMAND gg20.sign_n_n_mt_test)

    add_executable(gg20.sign_t_n_mt_test gg20/sign_t_n_mt_test.cpp)
    add_test(NAME gg20.sign_t_n_mt_test COMMAND gg20.sign_t_n_mt_test)
endif()

if (NOT ${NO_MPC_CMP})
    # cmp
    add_executable(cmp.minimal_key_gen_test cmp/minimal_key_gen_test.cpp CTimer.cpp)
    add_test(NAME cmp.minimal_key_gen_test COMMAND cmp.minimal_key_gen_test)

    add_executable(cmp.aux_info_key_refresh_test cmp/aux_info_key_refresh_test.cpp CTimer.cpp)
    add_test(NAME cmp.aux_info_key_refresh_test COMMAND cmp.aux_info_key_refresh_test)

    add_executable(cmp.sign_test cmp/sign_test.cpp CTimer.cpp)
    add_test(NAME cmp.sign_test COMMAND cmp.sign_test)

    add_executable(cmp.key_gen_test cmp/key_gen_test.cpp CTimer.cpp)
    add_test(NAME cmp.key_gen_test COMMAND cmp.key_gen_test)

    add_executable(cmp.key_recovery_test cmp/key_recovery_test.cpp CTimer.cpp)
    add_test(NAME cmp.key_recovery_test COMMAND cmp.key_recovery_test)

    # multi-thread
    add_executable(cmp.minimal_key_gen_mt_test cmp/minimal_key_gen_mt_test.cpp)
    add_test(NAME cmp.minimal_key_gen_mt_test COMMAND cmp.minimal_key_gen_mt_test)

    add_executable(cmp.aux_info_key_refresh_mt_test cmp/aux_info_key_refresh_mt_test.cpp)
    add_test(NAME cmp.aux_info_key_refresh_mt_test COMMAND cmp.aux_info_key_refresh_mt_test)

    add_executable(cmp.sign_n_n_mt_test cmp/sign_n_n_mt_test.cpp)
    add_test(NAME cmp.sign_n_n_test COMMAND cmp.sign_n_n_mt_test)

    add_executable(cmp.sign_t_n_mt_test cmp/sign_t_n_mt_test.cpp)
    add_test(NAME cmp.sign_t_n_test COMMAND cmp.sign_t_n_mt_test)
endif()

if (NOT ${NO_TIME})

    # cmp
    add_executable(time.cmp.sign_test time/cmp/sign_test.cpp CTimer.cpp)
    add_test(NAME time.cmp.sign_test COMMAND time.cmp.sign_test)

    add_executable(time.cmp.key_gen_test time/cmp/key_gen_test.cpp CTimer.cpp)
    add_test(NAME time.cmp.key_gen_test COMMAND time.cmp.key_gen_test)
    # gg18
    add_executable(time.gg18.sign_test time/gg18/sign_test.cpp CTimer.cpp)
    add_test(NAME time.gg18.sign_test COMMAND time.gg18.sign_test)
    ##gg20
    add_executable(time.gg20.sign_test time/gg20/sign_test.cpp CTimer.cpp)
    add_test(NAME time.gg20.sign_test COMMAND time.gg20.sign_test)
    ##Li24
    add_executable(time.Li24.sign_test time/Li24/sign_test.cpp CTimer.cpp)
    add_test(NAME time.Li24.sign_test COMMAND time.Li24.sign_test)

    # multi-thread
    #cmp
    add_executable(time.cmp.sign_t_n_mt_test time/cmp/sign_t_n_mt_test.cpp CTimer.cpp)
    add_test(NAME time.cmp.sign_t_n_test COMMAND time.cmp.sign_t_n_mt_test)
    #gg18
    add_executable(time.gg18.sign_t_n_mt_test time/gg18/sign_t_n_mt_test.cpp CTimer.cpp)
    add_test(NAME time.gg18.sign_t_n_test COMMAND time.gg18.sign_t_n_mt_test)

    add_executable(time.gg18.key_gen_mt_test time/gg18/key_gen_mt_test.cpp CTimer.cpp)
    add_test(NAME time.gg18.key_gen_mt_test COMMAND time.gg18.key_gen_mt_test)
    ##gg20
    add_executable(time.gg20.sign_t_n_mt_test time/gg20/sign_t_n_mt_test.cpp CTimer.cpp)
    add_test(NAME time.gg20.sign_t_n_test COMMAND time.gg20.sign_t_n_mt_test)
    ##Li24
    add_executable(time.Li24.key_gen_mt_test time/Li24/key_gen_mt_test.cpp CTimer.cpp)
    add_test(NAME time.Li24.key_gen_mt_test COMMAND time.Li24.key_gen_mt_test)

    add_executable(time.Li24.sign_t_n_mt_test time/Li24/sign_t_n_mt_test.cpp CTimer.cpp)
    add_test(NAME time.Li24.sign_t_n_test COMMAND time.Li24.sign_t_n_mt_test)
endif()


