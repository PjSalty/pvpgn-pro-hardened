add_executable(bnetsrp3_test bnetsrp3_test.cpp )
target_link_libraries(bnetsrp3_test PRIVATE common)
add_test(bnetsrp3_test bnetsrp3_test)

add_executable(bigint bigint.cpp )
target_link_libraries(bigint PRIVATE common)
add_test(bigint bigint)

# Guards the two fmt lifetime/pointer bugs upstream introduced with the fmt move
# (dangling _localize format string, "{}" + '\n' pointer arithmetic in the MOTD
# handler). Run under sanitizers via test/run-fmt-regression.sh as well.
add_executable(regression_fmt_lifetime regression_fmt_lifetime.cc)
target_link_libraries(regression_fmt_lifetime PRIVATE fmt)
add_test(regression_fmt_lifetime regression_fmt_lifetime)
