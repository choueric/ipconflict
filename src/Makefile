STARGET=libipconflict.a
DTARGET=libipconflict.so

SRCS=$(wildcard *.c)
OBJS=$(SRCS:%.c=%.o)
DEPS=$(SRCS:%.c=%.d)

CFLAGS=-Wall -Werror -g -O2 -std=gnu99 -fPIC -I../include

all:$(STARGET) $(DTARGET)

$(DEPS):%.d:%.c 
	@set -e rm -f $@
	$(CC) -MM $(CFLAGS) $< > $@.1234
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.1234 > $@
	@rm -f $@.1234

-include $(DEPS)

$(STARGET):$(OBJS)
	ar -r $@ $(OBJS)

$(DTARGET):$(OBJS)
	$(CC) $(OBJS) -shared -o $(DTARGET)

clean:
	rm -rf *.d *.o $(DTARGET) $(STARGET)
