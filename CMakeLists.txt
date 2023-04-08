cmake_minimum_required(VERSION 3.10)

project(KeyFobPAM)

add_library(keyfobpam MODULE src/pam.c src/aes.c src/sha3.c)
target_link_libraries(keyfobpam PRIVATE pam pam_misc qrencode)

add_executable(keyfob src/main.c src/aes.c src/sha3.c)
target_link_libraries(keyfob PRIVATE pam pam_misc qrencode)

add_executable(mysandbox src/mysandbox.c src/aes.c src/sha3.c)
target_link_libraries(mysandbox PRIVATE pam pam_misc qrencode)
