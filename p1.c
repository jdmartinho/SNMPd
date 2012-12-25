#include "gestao.h"

void menu() {

  printf("\n\n\nOpcoes: \n\n\t1 - (Re)definir rede.\n");
  printf("\t2 - Configurar um no da rede.\n");
  printf("\t3 - Construir mapa da rede.\n");
  printf("\t4 - Refrescar mapa da rede.\n");
  printf("\t5 - Ver informacao sobre um no da rede.\n");
  printf("\t6 - Descarregar informacao de um conjunto de nos.\n\n");
  printf("\t0 - Sair.\n\n");
  printf(">");

}

main() {
  rede_t rede;
  no_t *nos;
  int n_nos = -1;

  menu();
  int c = -1;
  while((c = fgetc(stdin)) != 0) {
    switch(c) {

    case '1':
      le_rede(&rede);
      n_nos = rede.max - rede.min + 1;
      nos = malloc(sizeof(no_t) * n_nos);
      gera_ips(&rede, nos, n_nos);

      menu();
      break;

    case '2':
      if (n_nos == -1) 
	printf("Nenhuma rede definida!\n");
      else 
	config_no(nos, n_nos);
      
      menu();
      break;

    case '3':
      if (n_nos == -1) 
	printf("Nenhuma rede definida!\n");
      else 
	gerar_mapa(&rede, nos, n_nos, NULL);
	
      menu();      
      break;

    case '4':
      if (n_nos == -1) 
	printf("Nenhuma rede definida!\n");
      else 
	 actualizar_mapa(&rede, nos, n_nos);
	
      menu();      
      break;

    case '5':
      if (n_nos == -1) 
	printf("Nenhuma rede definida!\n");
      else 
	ver_no(nos, n_nos);
      
      menu();
      break;

    case '6':
      if (n_nos == -1) 
	printf("Nenhuma rede definida!\n");
      else 
	info_nos(nos, n_nos);
	;
      
      menu();
      break;
      
    case '0':
      if (n_nos != -1) 
	free(nos);
      exit(0);
      break;

    default:
      break;
    }
    
  }//while
  
}


