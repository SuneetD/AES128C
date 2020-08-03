#define KEY_LEN_BYTES 16
#define KEY_EXP_SIZE 176
#define NK 4

typedef uint8_t state[4][4];

//void keyExpansion(uint8_t * roundkey, uint8_t* key);
void encrypt(state * message);
void decrypt(state *cipher);
void init(uint8_t *key);

//test funcs
void checkRoundKey();