#ifndef _GESTAO_H_
#define _GESTAO_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

typedef enum {DESCONHECIDO, SEM_SNMP, SNMP, SILENCIOSO} estado_t;

typedef struct rede {
  unsigned ip; //primeiro ip da rede
  unsigned mask;
  int min; // a gama de IPs comeca em min
  int max;
  long timeout;
  int tentativas;
  unsigned max_nos;

  time_t actual;
} rede_t;

typedef struct no {
  char ip[16];
  int porto;
  char *community;  //public ou private
  int versao;
  estado_t estado;
  char sysname[512]; // variavel system.sysName
} no_t;

void le_rede(rede_t *rede);
void gera_ips(rede_t *rede, no_t *nos, int n_nos);
void config_no(no_t *nos, int n_nos);
void gerar_mapa(rede_t * rede, no_t *nos, int n_nos, no_t *antigos);
void actualizar_mapa(rede_t * rede, no_t *nos, int n_nos);
void ver_no(no_t *nos, int n_nos);
void info_nos(no_t *nos, int n_nos);

#endif


