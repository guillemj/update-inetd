CFLAGS := -Wall -W -g -O2
CC := gcc

CFILES := addrfam.c execute.c config.c main.c archlinux.c
HFILES := header.h archlinux.h
PERL := defn2c.pl defn2man.pl
DEFNFILES := inet.defn ipx.defn inet6.defn

OBJ := main.o addrfam.o execute.o config.o \
	$(patsubst %.defn,%.o,$(DEFNFILES)) archlinux.o

MAN := $(patsubst %.defn,%.man,$(DEFNFILES))

default : executables
all : executables docs

executables : ifup ifdown ifup.8 ifdown.8 interfaces.5
docs : ifupdown.ps.gz ifupdown.pdf ifup.8.ps.gz interfaces.5.ps.gz

.PHONY : executables 
.PHONY : clean clobber

install :
	install -m 0755 -d     ${BASEDIR}/sbin
	install -m 0755 ifup   ${BASEDIR}/sbin
	ln ${BASEDIR}/sbin/ifup ${BASEDIR}/sbin/ifdown	

clean :
	rm -f *.aux *.toc *.log *.bbl *.blg *.ps
	rm -f *.o *.d $(patsubst %.defn,%.c,$(DEFNFILES)) *~
	rm -f $(patsubst %.defn,%.man,$(DEFNFILES))
	rm -f ifup ifdown interfaces.5 ifdown.8
	rm -f ifupdown.dvi *.ps{,.gz} ifupdown.pdf

clobber : clean
	rm -f ifupdown.tex $(PERL) $(CFILES) $(HFILES) $(DEFNFILES)

distclean : clobber
	rm -f makecdep.sh makenwdep.sh Makefile
ifup: $(OBJ)
	$(CC) $(CFLAGS) -o ifup $^

ifdown: ifup
	ln -sf ifup ifdown
interfaces.5: interfaces.5.pre $(MAN)
	LINE=$$(grep -n '^##ADDRESSFAM##$$' $< | sed 's/:.*//g'); \
	WC=`wc -l < $<`;                                          \
	(                                                         \
	  head -$$[$$LINE - 1] $<;                                \
	  cat $(MAN);                                             \
	  tail -$$[$$WC - $$LINE] $<;                             \
	) > $@

ifdown.8: ifup.8
	ln -sf $< $@

%.5.ps: %.5
	groff -mandoc -Tps $< > $@
%.8.ps: %.8
	groff -mandoc -Tps $< > $@
%.tex : %.nw
	noweave -index -latex $< >$@

%.bbl : %.tex biblio.bib
	latex $<
	bibtex $(basename $<)

%.dvi : %.tex %.bbl
	latex $<
	latex $<

%.pdf : %.tex %.bbl
	pdflatex $<
	pdflatex $<

%.ps : %.dvi
	dvips -o $@ $<

%.gz : %
	gzip --best --stdout $< >$@
%.d: %.nw makenwdep.sh
	./makenwdep.sh $< > $@
%.d: %.c makecdep.sh
	./makecdep.sh $< > $@
%.c : %.defn defn2c.pl
	./defn2c.pl $< > $@
%.man: %.defn defn2man.pl
	./defn2man.pl $< > $@

include ifupdown.d
