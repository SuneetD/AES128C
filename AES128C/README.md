# Suneet Dhaliwal, Test code implementing AES 128

# Usage 
 Code does no error checking on files(length/correct values). 

 Assumes key and plaintext are 16 bytes, and in the format on 1 line(hex values separated by spaces)
> xx xx xx xx xx xx .. xx (16 bytes in hex)

Usage is `./aes128 key.txt plaintext.txt` 



## Nuances

Need to call the init function for AES to setup schedule. Need to run init before anything else can be done.

SBox/RSBox are hard coded in aes.c, same for rcon.

