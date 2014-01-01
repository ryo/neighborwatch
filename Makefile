
PREFIX=	/usr/local

CC	= gcc
DBG	= -O3 # -g
CFLAGS	= $(DBG) -pipe -Wall
#CFLAGS+=-DNEIGHBORWATCH_MACDBDIR=\"$(PREFIX)/lib/neighborwatch/db\"
#CFLAGS+=-DNEIGHBORWATCH_LOGFILE=\"$(PREFIX)/lib/neighborwatch/neighborwatch.log\"
CFLAGS+=-DNEIGHBORWATCH_DATFILE=\"$(PREFIX)/lib/neighborwatch/neighborwatch.dat\"
CFLAGS+=-DNEIGHBORWATCH_ETHERCODEDAT=\"$(PREFIX)/lib/neighborwatch/ethercodes.dat\"
LD	= gcc
LIBS	= -lutil

PROGRAM	= neighborwatch
OBJS	= neighborwatch.o neighborwatch_bpf.o packet_record.o logdb.o ltsv.o oui.o


.c.o:
	$(CC) -c $(CFLAGS) $<

$(PROGRAM): $(OBJS)
	$(LD) $(OBJS) -o $(PROGRAM) $(LIBS)

clean:
	-rm -fr $(OBJS) $(PROGRAM)

cleandir: clean
	-rm -fr *.d .depend

install: $(PROGRAM) ethercodes.dat
	install -d -m 0755 $(PREFIX)/lib/neighborwatch/
	install -m 0755 neighborwatch $(PREFIX)/bin/
	install -m 0644 ethercodes.dat $(PREFIX)/lib/neighborwatch/


ethercodes.dat:
	mv -f ethercodes.dat ethercodes.dat.bak || true
	wget http://standards.ieee.org/regauth/oui/oui.txt
	perl ./ouitxt_convert.pl oui.txt > ethercodes.dat

neighborwatch_bpf.o: neighborwatch.h packet.h
ltsv.o: ltsv.h
packet_record.o: neighborwatch.h logdb.h packet.h
neighborwatch.o: neighborwatch.h neighborwatch_bpf.h logdb.h oui.h
oui.o: neighborwatch.h oui.h
logdb.o: neighborwatch.h oui.h logdb.h timewheelq.h ltsv.h
