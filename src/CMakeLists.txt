cmake_minimum_required(VERSION 3.10)
project(Perks)

# Create the executable from main.c
add_executable(Perks main.c)

# Link against bcrypt library
target_link_libraries(Perks bcrypt)
