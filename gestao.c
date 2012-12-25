#include <stdio.h>
#include <stdlib.h>
#include "gestao.h"

int pedidos = 0; // numero de pedidos assincronos em execucao

struct async_dados {
  struct snmp_session *sess;          
  oid actual[MAX_OID_LEN];   
  int tam;
  FILE *f;
}; 

#define PARTE(ip,a,b,c,d)			\
  a = (ip >> 24);				\
  b = (ip >> 16) & 0xff;			\
  c = (ip >> 8) & 0xff;				\
  d = ip & 0xff;

#define IP(ip,b,c,d)				\
  ip &= 0xff;					\
  ip <<= 8;					\
  ip |= b & 0xff;				\
  ip <<=8;					\
  ip |= c & 0xff;				\
  ip <<=8;					\
  ip |= d & 0xff;



void le_rede(rede_t *rede) {

  unsigned ip, b, c, d, n, mask = 0xffffffff;
  unsigned max_nos = 1;
  int min, max, tentativas;
  long timeout;
  min = max = timeout = tentativas = 0;

  printf("IP <a.b.c.d/n>: ");
  scanf("%u.%u.%u.%u/%u", &ip, &b, &c, &d, &n);

  mask <<= (32 - n);
  max_nos <<= (32 - n);

  // sem .255 e .0
  max_nos -= 2;

  while (min < 1 || min > max_nos) {
    printf("Primeiro IP: ");
    scanf("%d", &min);
  }

  while (max < min || max > max_nos) {
    printf("Ultimo IP: ");
    scanf("%d", &max);
  }

  printf("Tempo de espera (s): ");
  scanf("%ld", &timeout);

  printf("Tentativas: ");
  scanf("%d", &tentativas);

  IP(ip,b,c,d);
  ip &= mask;

#ifdef DEBUG
  printf("IP: %u.%u.%u.%u \n", 
	 ip >> 24, 
	 (ip >> 16) & 0xff,
	 (ip >> 8) & 0xff,
	 ip & 0xff
	 );
  printf("Rede: %u.%u.%u.%u \n",
	 mask >> 24, 
	 (mask >> 16) & 0xff,
	 (mask >> 8) & 0xff,
	 mask & 0xff
	 );

  printf("Numero maximo de nos na rede: %u \n", max_nos);
#endif

  rede->ip = ip;
  rede->mask = mask;
  rede->min = min;
  rede->max = max;
  rede->timeout = timeout * 1000000;
  rede->tentativas = tentativas;
  rede->max_nos = max_nos;
}


void gera_ips(rede_t *rede, no_t *nos, int n_nos) {
  unsigned ip, a, b, c, d;
 
  realloc(nos, n_nos * sizeof(no_t));
  PARTE(rede->ip, a, b, c, d);

  d = rede->min - 1; // se > 255 kaput
  int i = 0;
  for (; i < n_nos; i++) {
    d++;
    if (d >= 255) {
      c++;
      d = 1;
    }
      
    if (c >= 255) {
      b++;
      c = 1;
    }

    if (b >= 255) {
      a++;
      b = 1;
    }

    ip = a;
    
    IP(ip,b,c,d);

    sprintf(nos[i].ip, "%d.%d.%d.%d", a, b, c, d);

    nos[i].porto = 161;
    nos[i].community = strdup("public");
    nos[i].versao = SNMP_VERSION_2c;
 
  }// for

#ifdef DEBUG
  printf("IPs gerados: \n");
  for(i = 0; i < n_nos; i++)
    printf("IP do no [%d]: %s\n", i, nos[i].ip);
#endif

}

void config_no(no_t *nos, int n_nos) {
  int no, porto, str, versao;
  no = porto = str = versao = -1;

  while( no >= n_nos || no < 0) {
    printf("No a configurar: ");
    scanf("%d", &no);
  }

  printf("Porto: ");
  scanf("%d", &porto);

  while (str != 1 && str != 2) {
    printf("Community < 1 - private, 2 - public >:" );
    scanf("%d", &str);
  }
  
  while (versao < 1 || versao > 3) {
    printf("Versao SNMP [1-3]:" );
    scanf("%d", &versao);
  }
  
  nos[no].porto = porto;
  if (str == 1)
    nos[no].community = strdup("private");
  else
    nos[no].community = strdup("public");

  switch(versao) {
  case '1':
    nos[no].versao = SNMP_VERSION_1;
    break;
  case '2':
    nos[no].versao = SNMP_VERSION_2c;
    break;
  case '3':
    nos[no].versao = SNMP_VERSION_3;
    break;
    
  default:
    break;
  }
}

void gerar_mapa(rede_t * rede, no_t *nos, int n_nos, no_t *antigos) {
  // inicializacao SNMP 
  struct snmp_session session, *ss;
  struct snmp_pdu *pdu;
  struct snmp_pdu *response;
  struct variable_list *vars;
  // ping
  int status, ping_ret;
  
  init_snmp("cgs");

  int i = 0;
  for(; i < n_nos; i++) {
    char comando[64];
    sprintf(comando, "ping -W %d -c %d %s >> /dev/null", 1, 1, nos[i].ip);
    status = system(comando);
   
    if (-1 != status)
      ping_ret = WEXITSTATUS(status);

    if (ping_ret) {
      printf("==========================================\n");
      printf("No %d <%s> ", i, nos[i].ip);
      
      /* Verificar se o no ja respondeu anteriormente */
      if (antigos != NULL && antigos[i].estado != DESCONHECIDO) {
	nos[i].estado = SILENCIOSO;
	printf("SILENCIOSO\n");

	if (antigos[i].estado == SNMP)
	  printf("Este no tinha agente SNMP. sysName = %s\n", nos[i].sysname);
      }
      else {
	nos[i].estado = DESCONHECIDO;
	printf("DESCONHECIDO\n");
      }
      printf("==========================================\n");
    } else {
      //inicializar sessao snmp
      snmp_sess_init(&session);

      //concatenar ip:porto
      char pname[24];
      sprintf(pname, "%s:%d", nos[i].ip, nos[i].porto);
      session.peername = strdup(pname);
      //configurar a sessao de acordo com os parametros definidos para o no
      session.version = nos[i].versao;
      session.community = strdup(nos[i].community);
      session.community_len = strlen(session.community);

      session.timeout = rede->timeout;
      session.retries = rede->tentativas;

      if (!(ss = snmp_open(&session))) {
	snmp_perror("snmp_open");
	
      } else {
	oid ids[MAX_OID_LEN];
	int tam = MAX_OID_LEN;
	
	/* Criar a PDU para obter... */
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	
	/* Host Resources: numero de utilizadores */
	get_module_node("hrSystemNumUsers.0","HOST-RESOURCES-MIB", ids, &tam);
	snmp_add_null_var(pdu, ids, tam);
	
	/* Host Resources: processos */
	get_module_node("hrSystemProcesses.0","HOST-RESOURCES-MIB", ids, &tam);	
	snmp_add_null_var(pdu, ids, tam);
	
	/* System: nome */
	get_module_node("sysName.0", "RFC1213-MIB", ids, &tam);
	snmp_add_null_var(pdu, ids, tam);
	
	/* System: uptime */
	get_module_node("sysUpTime.0", "RFC1213-MIB", ids, &tam);
	snmp_add_null_var(pdu, ids, tam);
	      
	/* Fazer os pedidos sincronamente */
	status = snmp_synch_response(ss, pdu, &response);

	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
	  nos[i].estado = SNMP;
	  printf("########################################\n");
	  printf("O no %d <%s> TEM AGENTE SNMP\n", i, nos[i].ip);

	  int k = 0;
	  for(vars = response->variables; vars; vars = vars->next_variable) {
	    k++;
	    // mostrar resultados
	    print_variable(vars->name, vars->name_length, vars);
	    //print_value(vars->name, vars->name_length, vars);
	    // guardar sysName 
	    if (k == 3)
	      snprint_value(nos[i].sysname, sizeof(nos[i].sysname), 
			       vars->name, vars->name_length, vars);
	  }//for
	  printf("\n");
	  printf("########################################\n\n");
	} else {
	  nos[i].estado = SEM_SNMP;
	  printf("<-------------------------------------->\n");
	  printf("O no %d <%s> NAO TEM AGENTE SNMP\n", i, nos[i].ip);

	  if (antigos != NULL && antigos[i].estado == SNMP)
	    printf("Este no tinha agente SNMP. sysName = %s\n", nos[i].sysname);

	  printf("<-------------------------------------->\n");
	  /*
	  //ERRO
	  if (status == STAT_SUCCESS)
	    fprintf(stderr, "Erro: %s\n",
		    snmp_errstring(response->errstat));
	  else
	    snmp_sess_perror("snmp_synch_response", ss);
	  */
	} //if(status sem erros)
      }
    }

  }//for

  /* Actualizar tempo */
  rede->actual = time(NULL);
  
}//gerar_mapa


void actualizar_mapa(rede_t *rede, no_t *nos, int n_nos) {
  int i, tam_copia = n_nos * sizeof(no_t);  
  no_t *nos_copia = malloc(tam_copia);
  memcpy(nos_copia, nos, tam_copia);

  printf("Ultima actualizacao: %s\n", ctime(&rede->actual));	
  gerar_mapa(rede, nos, n_nos, nos_copia);
  printf("Nova actualizacao: %s\n", ctime(&rede->actual));

  free(nos_copia);  
}


void ver_mib(char *grupo, struct snmp_session *session) {
  struct snmp_session *ss;
  struct snmp_pdu *pdu;
  struct snmp_pdu *response;
  struct variable_list *vars;
  
  oid anOID[MAX_OID_LEN];
  int oidlen = MAX_OID_LEN;
  oid root[MAX_OID_LEN];
  int rootlen = MAX_OID_LEN;
  int running, status;
  int no_id;
  int check, count;

  /*
   * Obter OID para o grupo
   */
  rootlen = MAX_OID_LEN;
  if (snmp_parse_oid(grupo, root, &rootlen) == NULL) {
    snmp_perror(grupo);
    exit(1);
  }
   
  ss = snmp_open(session);
  if (ss == NULL) {
    snmp_sess_perror("snmp_open", session);
    exit(1);
  }

  /*
   * Comecar em "system" ou "hrSystem"
   */
  memmove(anOID, root, rootlen * sizeof(oid));
  oidlen = rootlen;

  running = 1;
  /*
   * Pedir a proxima variavel, sucessivamente ate ao fim da mib 
   */
  while (running) {
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    snmp_add_null_var(pdu, anOID, oidlen);
    
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
      if (response->errstat == SNMP_ERR_NOERROR) {

	for (vars = response->variables; vars;
	     vars = vars->next_variable) {
	 
	  if ((vars->name_length < rootlen)
	      || (memcmp(root, vars->name, rootlen * sizeof(oid))
		  != 0)) { // nao pertence ao grupo pedido
	    
	    running = 0;
	    continue;
	  }
	
	  print_variable(vars->name, vars->name_length, vars);
	  if ((vars->type != SNMP_ENDOFMIBVIEW) &&
	      (vars->type != SNMP_NOSUCHOBJECT) &&
	      (vars->type != SNMP_NOSUCHINSTANCE)) {
	   
	    memmove((char *) anOID, (char *) vars->name,
		    vars->name_length * sizeof(oid));
	    oidlen = vars->name_length;
	  } else {
	    printf("Erro! \n");
	    running = 0;
	  }
	}
      } else {
	/* ERRO */
	running = 0;
	if (response->errstat == SNMP_ERR_NOSUCHNAME) {
	  printf("Fim da MIB\n");
	} else {
	  fprintf(stderr, "Erro na reposta: %s\n", 
		  snmp_errstring(response->errstat));
	}
      }
    } else if (status == STAT_TIMEOUT) {
      fprintf(stderr, "Timeout: %s\n", session->peername);
      running = 0;
    } else {                /* status == STAT_ERROR */
      snmp_sess_perror("ver_mib", ss);
      running = 0;
    }
    if (response)
      snmp_free_pdu(response);
  }

  
}

void ver_no(no_t *nos, int n_nos) {
  struct snmp_session session;
  int no_id = -1;

  while (no_id > n_nos || no_id < 0) {
    printf("No [0-%d]: ", n_nos - 1);
    scanf("%d", &no_id);
  }
  snmp_sess_init(&session);
  
  char pname[25];
  sprintf(pname, "%s:%d", nos[no_id].ip, nos[no_id].porto);
  session.peername = strdup(pname);
  session.version = nos[no_id].versao;
  session.community = strdup(nos[no_id].community);
  session.community_len = strlen(session.community);
 

  printf("-------------> Grupo System <-------------- \n");
  ver_mib("system", &session);
  printf("-------------> Grupo hrSystem <------------ \n");  
  ver_mib("hrSystem", &session);

}


int 
processa(int operation, struct snmp_session *sp, int reqid, 
	 struct snmp_pdu *pdu, void *magic) {

  struct async_dados *dados = (struct async_dados *) magic;
  struct snmp_pdu *req;
  struct variable_list *vars = pdu->variables;


   
  if (operation != NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
    --pedidos;
    printf("Erro na resposta ou timeout.\n");
    fclose(dados->f);
  } else if (vars->type == SNMP_ENDOFMIBVIEW) {
    --pedidos;
    fprintf(dados->f,"========> Fim da MIB! <======== \n");  
    fclose(dados->f);
    printf("Ficheiro escrito! ID: %s\n", sp->peername);
  } else {
    fprint_variable(dados->f, vars->name, vars->name_length, vars);

    /* Actualizar OID */
    memmove((char *) dados->actual, (char *) vars->name,
	    vars->name_length * sizeof(oid));
    dados->tam =  pdu->variables->name_length;

    req = snmp_pdu_create(SNMP_MSG_GETNEXT);
    snmp_add_null_var(req, dados->actual, dados->tam);
    if (snmp_send(dados->sess, req))
      return 1;
    else {
      snmp_perror("snmp_send");
      snmp_free_pdu(req);
    }      
  
  }
}//processa


void info_nos(no_t *nos, int n_nos) {
  pedidos = 0;   
  int i, ipi = -1, ipf = -1;
  
  //pedir a gama de ip's
  while( ipi < 0 || ipi > n_nos)	{
    printf("No inicial: ");
    scanf("%d", &ipi);
  }
  while(ipf < ipi || ipi > n_nos) {
    printf("No final: ");
    scanf("%d", &ipf);
  }
  //fazer pedido assincrono

  struct async_dados dados[ipf + 1 - ipi]; 

  for(i = ipi; i <= ipf; i++) {
    if (nos[i].estado == SNMP) {
      
      struct snmp_pdu *req;
      struct snmp_session session;
      snmp_sess_init(&session);                   
     
      // configurar sessao
      char pname[25];
      sprintf(pname, "%s:%d", nos[i].ip, nos[i].porto);
      session.peername = strdup(pname);
      session.version = nos[i].versao;
      session.community = strdup(nos[i].community);
      session.community_len = strlen(session.community);

      session.callback = processa;            
      session.callback_magic = &dados[i];

      if (!(dados[i].sess = snmp_open(&session))) {
	snmp_perror("snmp_open");
	continue;
      }

      //criar ficheiro 
      sprintf(pname, "%s.out", nos[i].ip);
      dados[i].f = fopen(pname, "w");
      time_t tempo = time(NULL);
      fprintf(dados[i].f, "IP: %s \t %s\n", nos[i].ip, ctime(&tempo));
    

      oid mib[MAX_OID_LEN];
      int mib_len = MAX_OID_LEN;

      req = snmp_pdu_create(SNMP_MSG_GETNEXT);    
      read_objid("1.3.6.1.2.1", mib, &mib_len);
      snmp_add_null_var(req, mib, mib_len);
     
      memcpy(dados[i].actual, mib, mib_len);
      dados[i].tam = mib_len;

      if (snmp_send(dados[i].sess, req)) {
	pedidos++;
	printf("Foi pedida a MIB do no %d <%s>\n", i, nos[i].ip);
      }
      else {
	snmp_perror("snmp_send");
	snmp_free_pdu(req);
      }
    } else 
      printf("O no %d <%s> nao tem SNMP.\n", i, nos[i].ip);
  }

  /* Esperar até todos os nos responderem */
  while (pedidos) {
    int fds = 0, block = 1;
    fd_set fdset;
    struct timeval timeout;

    FD_ZERO(&fdset);
    snmp_select_info(&fds, &fdset, &timeout, &block);
    fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);


    if (fds) snmp_read(&fdset);
    else snmp_timeout();
  }
   
}

