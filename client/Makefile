CC=gcc
EXEC=client

DEPLIBS=../cnetlib/src/libcnetlib.a ../src/libipconflict.a
LIBS=$(DEPLIBS) -lpthread
INC=-I../include -I../cnetlib/include
CFLAGS=-Wall -Werror -g -O2 -std=gnu99 $(INC)

SRC=main.c
SUBDIRS=../cnetlib/src ../src
OBJS=$(SRC:%.c=%.o)

export

.PHONY: all subdir $(SUBDIRS) clean

all: subdir $(EXEC)

-include $(SRC:%.c=%.d)

subdir:$(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(EXEC): $(OBJS) $(DEPLIBS)
	$(CC) $< -o $(EXEC) $(LIBS)

$(DEPS):%.d:%.c 
	@set -e rm -f $@
	$(CC) -MM $(CFLAGS) $< > $@.1234
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.1234 > $@
	@rm -f $@.1234

clean_dirs := $(addprefix _clean_,$(SUBDIRS) )

$(clean_dirs):
	$(MAKE) -C $(patsubst _clean_%,%,$@) clean

clean: $(clean_dirs)
	rm -rf $(EXEC) *.d *.o
