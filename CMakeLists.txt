cmake_minimum_required(VERSION 3.10)

project(MyPAM)

add_library(mypam MODULE src/mypam.c src/aes.c src/sha3.c)
target_link_libraries(mypam PRIVATE pam pam_misc qrencode)

add_executable(myapp src/myapp.c src/aes.c src/sha3.c)
target_link_libraries(myapp PRIVATE pam pam_misc qrencode)

add_executable(mysandbox src/mysandbox.c src/aes.c src/sha3.c)
target_link_libraries(mysandbox PRIVATE pam pam_misc qrencode)
