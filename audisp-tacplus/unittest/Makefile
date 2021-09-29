#disable some warning because UT need test functions not in header file.
CFLAGS = -Wno-parentheses -Wno-format-security -Wno-implicit-function-declaration -c
IFLAGS = -I.. -I../include -I../lib
MFLAG = -DDEBUG -DUNIT_TEST

all:
	gcc user_secret_test.c $(IFLAGS) $(CFLAGS) -o user_secret_test.o
	gcc mock_helper.c $(IFLAGS) $(CFLAGS) -o mock_helper.o
	gcc ../user_secret.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o user_secret.o
	gcc ../regex_helper.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o regex_helper.o
	gcc ../trace.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o trace.o
	gcc  user_secret_test.o  mock_helper.o user_secret.o regex_helper.o trace.o -o user_secret_test  -lc -lcunit 

test:
	# run unit test, if UT failed, build will break
	./user_secret_test

clean:
	rm *.o
	rm user_secret_test
