# You can set additional flags on the command line.
# 
# make CFLAGS="-g"    # add debug information to build
# make LDFLAGS="-L/usr/local/lib" # add /usr/local/lib to build path
# and so on. A full list of Makefile implicit variables is here: https://t.ly/4CzEu

LDLIBS += -lm  # needed for floating point bugs using feenableexcept (see driver.c)

all: harness
harness: harness.o driver.o
clean:
	rm -f harness *.o
