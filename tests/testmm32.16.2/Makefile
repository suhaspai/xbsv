
BSCFLAGS=-aggressive-conditions -show-schedule -keep-fires -p +:../paclib

XBSVDIR=../..
DBNDIR=../../examples/testmm
DBNTOPBSV=$(DBNDIR)/Top.bsv
TESTCPPFILES=$(DBNDIR)/testmm.cpp
XBSVFLAGS = -D J_VALUE=32 -D K_VALUE=16 -D N_VALUE=2
include $(DBNDIR)/Makefile.dbn
