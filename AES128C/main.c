#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"

// returns 0 if fail, otherwise returns 1
int getFileContents(const char *fname, uint8_t *dest){
  FILE *file = fopen(fname, "r");
  char buf[10];
  int count = 0;

  if(file == NULL){
    printf("File not found: %s\n", fname);
    return 0;
  } else {
    while(fscanf(file, "%s", buf) == 1){
      dest[count] = (uint8_t)strtol(buf, NULL, 16);
      count ++;
    }
  }

  fclose(file);
  return 1;
}

int main(int argc, const char* argv[]){
  uint8_t key[16];// = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t plaintext[16];
  
  if(argc < 3){
    printf("Usage: ./aes128 keyfile.txt plaintext.txt\n");
    return 0;
  }

  if(!getFileContents(argv[1], key) || !getFileContents(argv[2], plaintext)){
    return 0;
  }
  
  init(key);
  checkRoundKey();

  printf("ENCRYPTION PROCESS\n------------------\n");
  encrypt((state *)plaintext);

  printf("DECRYPTION PROCESS\n------------------\n");
  decrypt((state *)plaintext); 

  //** TEST CODE BELOW
  // checkRoundKey();
  //keyExpansion(roundKey, key);

  // check key expansion correctness
  // for(int i = 0; i < KEY_EXP_SIZE; i++){
  //   if(i % 4 == 0  && i != 0){
  //     printf("\n");
  //   }
  //   printf("%x", roundKey[i]);
  // }

  printf("Done Processing!\n");
  return 0; 
}