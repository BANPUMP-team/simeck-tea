/*      SIMECK-TEA is a configurable lightweight cipher made of external SIMECK rounds and internal TEA rounds producing random-looking output
 *
 *      (C) 2024 Alin-Adrian Anton <alin.anton@cs.upt.ro>
 *
 *      A 3 by 5 configuration passes dieharder, ent, NIST and AIS31 randomness tests.
 *
 * 	Using MIT licensed code from Bo Zhu for SIMECK64 https://github.com/bozhu/Simeck paper https://eprint.iacr.org/2015/612.pdf
 * 	and TEA sample from David Wheeler's and Roger Needham's paper https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
 *
 * 	MIT License
 */

// Example of how to use

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include <argon2.h> /* libargon2 */
#define ARGON_HASHLEN 32
#define ARGON_SALTLEN 16

#define MAXPWDLEN 32

#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

void split_uint64_to_uint32(uint64_t value, uint32_t *result) {
    union {
        uint64_t value64;
        uint32_t value32[2];
    } u;
    u.value64 = value;
    result[0] = u.value32[0];
    result[1] = u.value32[1];
}

void simeckTeaCTR(const uint32_t master_key[], const uint32_t plaintext[], uint32_t ciphertext[], 
		int simeckrounds, int tearounds) {
    int idx;
    static uint64_t cnt = 0;
    uint32_t plain[2];
    split_uint64_to_uint32(cnt, plain);

    uint32_t keys[4] = {
        master_key[0],
        master_key[1],
        master_key[2],
        master_key[3],
    };
    ciphertext[0] = plain[0];
    ciphertext[1] = plain[1];
    uint32_t temp;

    uint32_t constant = 0xFFFFFFFC;
    uint64_t sequence = 0x938BCA3083F;

    for (idx = 0; idx < simeckrounds; idx++) {
        ROUND64(
                keys[0],
                ciphertext[1],
                ciphertext[0],
                temp
        );

        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND64(
                constant,
                keys[1],
                keys[0],
                temp
        );

        // rotate the LFSR of keys
        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;

	uint32_t y=ciphertext[0], z=ciphertext[1], sum=0, delta=0x9e3779b9; /* a key schedule constant */
        while (tearounds-->0) { /* basic cycle start */
            sum += delta;
            y += ((z<<4) + keys[0]) ^ (z+sum) ^ ((z>>5) + keys[1]);
            z += ((y<<4) + keys[2]) ^ (y+sum) ^ ((y>>5) + keys[3]);
        } /* end cycle */
        ciphertext[0]=y; ciphertext[1]=z; 
    }
    ciphertext[0] ^= plaintext[0]; 
    ciphertext[1] ^= plaintext[1]; 
    cnt++; // counter mode..
}

int isStrongPassword(const char *password) {
    int length = strlen(password);

    // Criteria for a strong password
    int hasUpper = 0;
    int hasLower = 0;
    int hasDigit = 0;
    int hasSpecial = 0;

    // Check each character of the password
    for (int i = 0; i < length; i++) {
        if (isupper(password[i])) {
            hasUpper = 1;
        } else if (islower(password[i])) {
            hasLower = 1;
        } else if (isdigit(password[i])) {
            hasDigit = 1;
        } else if (ispunct(password[i])) {
            hasSpecial = 1;
        }
    }

    // Password is strong if all criteria are met
    return length >= 10 && hasUpper && hasLower && hasDigit && hasSpecial;
}

void copy_bytes_to_uint32(const uint8_t *source, uint32_t *destination, size_t elements) {
    typedef union {
        uint32_t value;
	uint8_t parts[4];
    } CopyUnion;
	
    for (size_t i = 0; i < elements; ++i) {
        CopyUnion u;

	for (int j = 0; j < 4; ++j) {
	    u.parts[j] = source[i * 4 + j]; // Copy 4 bytes at a time
	}

	destination[i] = u.value;
    }
}

int main(int argc, char *argv[]) {
    // get input file and out file names
	if (argc != 5) {
		fprintf(stderr, "Usage: %s input-filename output-filename #simeckrounds #tearounds\n", argv[0]);
		fprintf(stderr, "          good randomness at 5 external rounds by 5 internal rounds\n");
		return 0;
    }

    // check if input file exists
    struct stat statbuf;
    if (stat(argv[1], &statbuf) == -1) {
	    perror("stat()");
	    return 1;
    }

    // read password without printing echo bytes on screen
    char passwd[MAXPWDLEN];
    uint32_t derived_key[4];
    struct termios original,noecho;

    tcgetattr(STDIN_FILENO, &original);
    noecho = original;
    noecho.c_lflag = noecho.c_lflag ^ ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    printf("Password: ");
    fgets(passwd, MAXPWDLEN, stdin);
    fprintf(stdout, "\n");
    uint32_t pwdlen = strlen((char *)passwd);
    passwd[pwdlen-1] = '\0';
    pwdlen--;
    tcsetattr(STDIN_FILENO, TCSANOW, &original);

    // check password strength
    if (!isStrongPassword(passwd)) { // cracklib is better
	fprintf(stderr, "Weak password.\n Use uppercase, lowercase, digits and special chars -- at least 10 bytes long.\n");
	return (10);
    }	 

    // expand password to 128 bits
    uint32_t t_cost = 20;       // 2-pass computation
    uint32_t m_cost = (1<<16);  // 64mb memory usage
    uint32_t parallelism = 1;   // number of threads

    uint8_t hash[ARGON_HASHLEN];
    uint8_t salt[ARGON_SALTLEN];
    memset(salt, 0x00, ARGON_SALTLEN);

    argon2i_hash_raw(t_cost, m_cost, parallelism, passwd, pwdlen, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);
    copy_bytes_to_uint32(hash, derived_key, 4);         // 4 * 32 = 128 bits


    // read input file
    FILE *fp, *fpout;
    off_t fsize = statbuf.st_size;
    fpout = fopen(argv[2], "w");
    if (fpout == NULL) {
	    perror("fopen() for writing");
	    return 3;
    }
    fp = fopen(argv[1], "rb+");
    if (fp == NULL) {
        perror("fopen() for reading");
        return 2;
    }

    uint32_t plaintext[2], ciphertext[2];
    uint32_t simeckrounds = strtol(argv[3], NULL, 10);
    uint32_t tearounds = strtol(argv[4], NULL, 10);

    if ((simeckrounds > 44) || (tearounds > 32)) {
	fprintf(stderr, "Simeckrounds maximum value is 44, Tearounds maximum value is 32, try 5 by 5\n");
	exit(EXIT_FAILURE);
    }
    
    int ret = 8;
    while(ret == 8) {
       if ((ret = fread(plaintext, 1, 8, fp))==0) { // read 64 bits
	        if (ferror(fp)) {
	            perror("fread()");
        	    exit(EXIT_FAILURE);
	        }
        }

        simeckTeaCTR(derived_key, plaintext, ciphertext, simeckrounds, tearounds);

        if (fwrite(ciphertext, 8, 1, fpout)!=1) { // write 64 bits of ciphertext
            perror("fwrite()");
            exit(EXIT_FAILURE);
        }
    }

    fclose(fp); 
    fclose(fpout);

    if (truncate(argv[2], fsize) == -1) {
	    perror("truncate() output file");
	    exit(EXIT_FAILURE);
    }

    return 0;
}

