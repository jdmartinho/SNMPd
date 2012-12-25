CC = gcc
FLAGS = -g -DDEBUG `net-snmp-config --libs`
#FICH_TAR = "projecto1.tar"
#FICH_TAR_GZ = "projecto1.tar.gz"
#DESTINO = "maqdestino:dirdestino"

tudo: p1 
	@echo "########### Tudo Feito ###############"

p1: p1.o gestao.o
	$(CC) $(FLAGS) -o $@ p1.o gestao.o 

#gestao: gestao.o
#	$(CC) $(FLAGS) -o $@ gestao.o 


#############################################################
clean:
	rm -f *.o *~ p1 gestao #$(FICH_TAR) $(FICH_TAR_GZ)

seguranca: clean
	tar -cf $(FICH_TAR) *.c *.h Makefile
	gzip $(FICH_TAR)
	scp $(FICH_TAR_GZ) $(DESTINO)


#######################################################
# Regra por omissao                                   #
#######################################################
%.o: %.c
	$(CC) $(FLAGS) -c $<
