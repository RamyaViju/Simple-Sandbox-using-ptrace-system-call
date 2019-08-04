###################################################################
#	This is the makefile that creates the fend executable 
#
#	-----------------------------------
#	Author: Ramya Vijayakumar
#	-----------------------------------
##################################################################

.PHONY: clean help .depend

#EXE = sandbox
EXE = fend
#SOURCES = $(wildcard src/*.c)
SOURCES = fend.c
OBJECTS = $(SOURCES:.c=.o)
#DEPS = $(OBJECTS:.o=.d)

CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -std=c11 -g
#CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wno-unknown-warning -std=c11 -g
CPPFLAGS = -I./includes -MD -MP
LDFLAGS =

all: $(EXE) LOGFILE

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(DEPS) $(EXE)
	rm -f ./fend.log
	find . -name "*~" -delete

help:
	@echo "make          Build $(EXE)"
	@echo "make deps     Generate .depends"
	@echo "make clean    Delete compilation files"
	@echo "make help     Print this help message"

LOGFILE:
	touch ./fend.log
