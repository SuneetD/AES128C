#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"


static uint8_t roundKey[KEY_EXP_SIZE];

// private functions
static void RotWord(uint8_t *rotWord);
static void SubWord(uint8_t *subWord);
static void keyExpansion(uint8_t * roundkey, uint8_t* key);
static uint8_t getSBoxValue(uint8_t n);
static void addRoundKey(uint8_t currRound, state *message);
static void subBytes(state * message);
static void shiftRows(state * message);
static void mixColumns(state *message);

static void invShiftRows(state * cipher);
static void invSubBytes(state *cipher);
static uint8_t getRSBoxValue(uint8_t n);
static void invMixColumns(state *cipher);

static void copyMatrix(state *msg, state *msgCp);

// helper functions
// static void printWord(uint8_t * word);
// static void printBitLength(uint8_t * word);
static void printState(state * word);

const uint8_t sbox[256]= { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                           0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                           0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                           0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                           0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                           0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                           0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                           0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                           0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                           0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                           0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                           0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                           0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                           0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                           0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                           0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

const uint8_t rsbox[256]= { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const uint8_t rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void init(uint8_t *key){
  keyExpansion(roundKey, key);
}

void encrypt(state * message){
  int currRound = 0;

  printf("plaintext: \n");
  printState(message);

  // add first ruondkey
  addRoundKey(currRound, message);

  // now round 1- 10
  for (currRound = 1; currRound < 10; currRound++){
    printf("ROUND %d\n----------\n", currRound);
    printState(message);

    subBytes(message);
    shiftRows(message);

    mixColumns(message);
    
    addRoundKey(currRound, message);
  }

  printf("FINAL ROUND\n-------------\n");
  printState(message);

  // last round now, no mixColumns
  subBytes(message);
  shiftRows(message);
  addRoundKey(currRound, message);

  printf("CIPHERTEXT:\n");
  printState(message);
}

void decrypt(state *cipher){
  // start from 10 since we are going backwards
  int currRound = 10;
  
  printf("CIPHERTEXT:\n");
  printState(cipher);

  addRoundKey(currRound, cipher);

  for (currRound = 9; currRound > 0; currRound--){
    printf("ROUND %d\n----------\n", abs(currRound - 10));
    printState(cipher);

    invShiftRows(cipher);
    invSubBytes(cipher);
    addRoundKey(currRound, cipher);
    invMixColumns(cipher);
  }

  printf("FINAL ROUND\n-------------\n");
  printState(cipher);

  invShiftRows(cipher);
  invSubBytes(cipher);
  addRoundKey(0, cipher);

  printf("MESSAGE:\n");
  printState(cipher);
}

static uint8_t mult(uint8_t x, uint8_t y){
  uint8_t result = 0;
  int hiBit, i;

  for (i = 0; i < 8; ++i){
    if((y & 1) != 0){
      result ^= x; 
    }

    hiBit = (x & 0x80) != 0;

    x <<= 1;

    if(hiBit){
      x ^= 0x1b;
    }

    y >>= 1;
  }

  return result;
}

static void invMixColumns(state *cipher){
  state *cipherCopy = malloc(16*sizeof(uint8_t));;
  copyMatrix(cipher, cipherCopy);
  int i;

  for (i = 0; i < 4; i++){
    /*
    *e, b, d, 9
    *9, e, b, d
    *d, 9, e, b
    *b, d, 9, e
    */

    cipher[0][i][0] = mult(0x0e, cipherCopy[0][i][0]) ^ mult(0x0b, cipherCopy[0][i][1]) ^ mult(0x0d, cipherCopy[0][i][2]) ^ mult(0x09, cipherCopy[0][i][3]);
    cipher[0][i][1] = mult(0x09, cipherCopy[0][i][0]) ^ mult(0x0e, cipherCopy[0][i][1]) ^ mult(0x0b, cipherCopy[0][i][2]) ^ mult(0x0d, cipherCopy[0][i][3]);
    cipher[0][i][2] = mult(0x0d, cipherCopy[0][i][0]) ^ mult(0x09, cipherCopy[0][i][1]) ^ mult(0x0e, cipherCopy[0][i][2]) ^ mult(0x0b, cipherCopy[0][i][3]);
    cipher[0][i][3] = mult(0x0b, cipherCopy[0][i][0]) ^ mult(0x0d, cipherCopy[0][i][1]) ^ mult(0x09, cipherCopy[0][i][2]) ^ mult(0x0e, cipherCopy[0][i][3]);
    
  }

  free(cipherCopy);
}

static void invSubBytes(state *cipher){
  int i,j;
  for(i = 0; i < 4; i ++){  
    for (j = 0; j < 4; j++){
      cipher[0][i][j] = getRSBoxValue(cipher[0][i][j]); 
    } 
  }
}

// same as shiftrows, except inversion is 4-n
static void invShiftRows(state* cipher){
  uint8_t temp;
  // 1st row stays the same, so its 'done'

  // 4th row shifted by 1
  temp = cipher[0][0][3];
  cipher[0][0][3] = cipher[0][1][3];
  cipher[0][1][3] = cipher[0][2][3];
  cipher[0][2][3] = cipher[0][3][3];
  cipher[0][3][3] = temp;

  // 3rd row shifted by 2
  temp = cipher[0][0][2];
  cipher[0][0][2] = cipher[0][2][2];
  cipher[0][2][2] = temp;
  temp = cipher[0][1][2];
  cipher[0][1][2] = cipher[0][3][2];
  cipher[0][3][2] = temp;

  // 2nd by 3
  temp = cipher[0][0][1];
  cipher[0][0][1] = cipher[0][3][1];
  cipher[0][3][1] = cipher[0][2][1];
  cipher[0][2][1] = cipher[0][1][1];
  cipher[0][1][1] = temp;
}

static void mixColumns(state *message){
  state *messageCopy = malloc(16*sizeof(uint8_t));;
  copyMatrix(message, messageCopy);
  int i;

  for (i = 0; i < 4; i++){
    /*
    *2, 3, 1, 1
    *1, 2, 3, 1
    *1, 1, 2, 3
    *3, 1, 1, 2
    */

    message[0][i][0] = mult(0x02, messageCopy[0][i][0]) ^ mult(0x03, messageCopy[0][i][1]) ^ messageCopy[0][i][2] ^ messageCopy[0][i][3];
    message[0][i][1] = messageCopy[0][i][0] ^ mult(0x02, messageCopy[0][i][1]) ^ mult(0x03, messageCopy[0][i][2]) ^ messageCopy[0][i][3];
    message[0][i][2] = messageCopy[0][i][0] ^ messageCopy[0][i][1] ^ mult(0x02, messageCopy[0][i][2]) ^ mult(0x03, messageCopy[0][i][3]);
    message[0][i][3] = mult(0x03, messageCopy[0][i][0]) ^ messageCopy[0][i][1] ^ messageCopy[0][i][2] ^ mult(0x02, messageCopy[0][i][3]);
    
  }

  free(messageCopy);
}

static void copyMatrix(state *msg, state *msgCp){
  memcpy(msgCp, msg, 16 * sizeof (state) );
}

static void shiftRows(state * message){
  uint8_t temp;
  // 1st row stays the same, so its 'done'

  // 2nd row shifted by 1
  temp = message[0][0][1];
  message[0][0][1] = message[0][1][1];
  message[0][1][1] = message[0][2][1];
  message[0][2][1] = message[0][3][1];
  message[0][3][1] = temp;

  // 3rd row shifted by 2
  temp = message[0][0][2];
  message[0][0][2] = message[0][2][2];
  message[0][2][2] = temp;
  temp = message[0][1][2];
  message[0][1][2] = message[0][3][2];
  message[0][3][2] = temp;

  // 4th by 3
  temp = message[0][0][3];
  message[0][0][3] = message[0][3][3];
  message[0][3][3] = message[0][2][3];
  message[0][2][3] = message[0][1][3];
  message[0][1][3] = temp;
}

static void subBytes(state * message){
  int i, j;
  for(i = 0; i < 4; i ++){  
    for (j = 0; j < 4; j++){
      message[0][i][j] = getSBoxValue(message[0][i][j]); 
    } 
  }
}

static void addRoundKey(uint8_t currRound, state *message){
  int i, j;
  for(i = 0; i < 4; i++){
    for(j =0; j < 4; j++){
      message[0][i][j] ^= roundKey[(currRound * 4 /*Nb*/ * 4) + (i * 4 /*Nb*/) + j];
    }
  }
}

static void keyExpansion(uint8_t * roundkey, uint8_t* key){
  // round 1 == key
  int i, j;
  uint8_t tempWord[4];
  
  for(i = 0; i < NK; i++){
    roundkey[i * 4] = key[i * 4];
    roundkey[(i * 4) + 1] = key[(i * 4) + 1];
    roundkey[(i * 4) + 2] = key[(i * 4) + 2];
    roundkey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  for(i = NK; i < 44/* init col * (rounds + 1) = 4 *(10+1) */; i++){
    j  = 4 * (i - 1); // get offset
    tempWord[0] = roundkey[j];
    tempWord[1] = roundkey[j + 1];
    tempWord[2] = roundkey[j + 2];
    tempWord[3] = roundkey[j + 3];

    if(i % NK == 0){
      RotWord(tempWord); /* can probably use for shiftrows */
      SubWord(tempWord);
      tempWord[0] = tempWord[0] ^ rcon[i/NK];
    }

    roundkey[(i * 4)]     = roundkey[(i - NK) * 4] ^ tempWord[0];
    roundkey[(i * 4) + 1] = roundkey[(i - NK) * 4 + 1] ^ tempWord[1];
    roundkey[(i * 4) + 2] = roundkey[(i - NK) * 4 + 2] ^ tempWord[2];
    roundkey[(i * 4) + 3] = roundkey[(i - NK) * 4 + 3] ^ tempWord[3];

  }
}

static void RotWord(uint8_t *rotWord){
  uint8_t temp;

  temp = rotWord[0];
  rotWord[0] = rotWord[1];
  rotWord[1] = rotWord[2];
  rotWord[2] = rotWord[3];
  rotWord[3] = temp;
}

static void SubWord(uint8_t *subWord){
  subWord[0] = getSBoxValue(subWord[0]);
  subWord[1] = getSBoxValue(subWord[1]);
  subWord[2] = getSBoxValue(subWord[2]);
  subWord[3] = getSBoxValue(subWord[3]); 
}

static uint8_t getRSBoxValue(uint8_t n){
  return rsbox[n];
}

static uint8_t getSBoxValue(uint8_t n){
  return sbox[n];
}

// HELPER FUNCTIONS

void checkRoundKey(){
  //check key expansion correctness
  int i;
  printf("\nKeySched\n---------\n");
  for(i = 0; i < KEY_EXP_SIZE; i++){
    if(i % 4 == 0  && i != 0){
      printf("\n");
    }
    printf("%hhx", roundKey[i]);
  }
  printf("\n\n");
}

// static void printBitLength(uint8_t * word){
//   for(int i = 0; i < 16; i ++){       
//     printf("%02hhx ", word[i]);
//   }
//   printf("\n");
// }

static void printState(state * word){
  int i,j;
  for(i = 0; i < 4; i ++){  
    for (j = 0; j < 4; j++){
      printf("%02hhx ", word[0][j][i]); //print like NIST 
    } 
    printf("\n");
  }
  printf("\n");

}

// static void printWord(uint8_t * word){
//   for(int i = 0; i < 4; i ++){       
//     printf("%02hhx ", word[i]);
//   }
//   printf("\n");
// }