# IDA-Finder
A Script that will loop though all client labled functions in IDA, and attept to find unique byte sequences
It will then create a .idc script file which can be used to find the functions in a future version of your input file

Currently this only works with PPC, but this can be changed by modifying the OP codes in isOPStatic
Note that if your database is large, this will take a long time to compleate the finding, as it is performing a binary search on every single byte until it finds a unique pattern
