/*      SmackTEA is a lightweight cipher made of external SIMECK rounds and internal TEA rounds producing random-looking output
 *
 *      (C) 2024 Alin-Adrian Anton <alin.anton@cs.upt.ro>
 *
 *      A 5 by 7 configuration passes dieharder, ent, NIST, AIS31 randomness tests and LIL.
 *
 * 	Using MIT licensed code from Bo Zhu for SIMECK64 https://github.com/bozhu/Simeck paper https://eprint.iacr.org/2015/612.pdf
 * 	and TEA sample from David Wheeler's and Roger Needham's paper https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
 *
 * 	MIT License
 */

// Demo code

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include <utime.h>
#include <fcntl.h>
#include <errno.h>



/* you may define these two strings as you wish in order to describe your product */
#define PRODUCTSERIALNO "SN:MAC:ADDDR:part"
#define PRODUCTVERSION "1st-of-June-2024-b6"

#define MAXPWDLEN 32

#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

uint8_t psum;
uint8_t pmul;
uint64_t IV; // initialization vector for block counter mode (CTR)
uint64_t cnt = 0; // couter for CTR mode

/* 
 * code snippets for pseudorandom number generator from Numerical Recipes by William H. Press, Saul A. Teukolsky,
 *      William T. Vetterling and Brian P. Flannery.
 */

uint64_t v = 4101842887655102017LL;
uint64_t vv = 2685821657736338717LL;

uint64_t int64() {
	v ^= v >> 21; 
	v ^= v << 35; 
	v ^= v >> 4;
	return v * vv;
}

uint32_t Random32(uint64_t seed) {
	v ^= seed;
	v = int64();

	return (uint32_t) v;
}


void seed(uint64_t seed) {
	Random32(seed);
}

uint32_t int32() { 
	return (uint32_t) int64(); 
} 


uint64_t Random64(uint64_t seed) {
	v ^= seed;
	v = int64();

	return v;
}

double RandomDouble() { 
	return 5.42101086242752217E-20 * int64(); 
}

/* 
 * Fowler–Noll–Vo hash 1a for output file filename
 */

uint64_t fnv1a_hash(const char *data, size_t length) {
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV-1a 64-bit offset basis
    uint64_t prime = 0x100000001b3ULL;     // FNV-1a 64-bit prime

    for (size_t i = 0; i < length; i++) {
        hash ^= (uint8_t)data[i];  // XOR with the byte from the data
        hash *= prime;             // Multiply by the FNV prime
    }

    return hash;
}


void print_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}


void get_modification_time_string(const struct timespec *mod_time, char *time_str, size_t max_len) {
    struct tm *tm_info = localtime(&mod_time->tv_sec);
    strftime(time_str, max_len, "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(time_str + strlen(time_str), max_len - strlen(time_str), ".%09ld", mod_time->tv_nsec);
}

void print_modification_time(const char *time_str) {
    printf("Modification time: %s\n", time_str);
}


void split_uint64_to_uint32(uint64_t value, uint32_t *result) {
    result[0] = (uint32_t)((value >> 32) & 0xFFFFFFFF); // Upper 32 bits
    result[1] = (uint32_t)(value & 0xFFFFFFFF);       // Lower 32 bits
}


uint64_t combine_uint32_to_uint64(const uint32_t *values) {
    return ((uint64_t)values[0] << 32) | values[1]; // Combine upper and lower 32 bits
}

void simeckTeaECB(const uint32_t master_key[], const uint32_t plaintext[], uint32_t ciphertext[]) { 
    int idx, simeckrounds = 5, tearounds = 7;
    uint32_t keys[4] = {
        master_key[0],
        master_key[1],
        master_key[2],
        master_key[3],
    };
    ciphertext[0] = plaintext[0];
    ciphertext[1] = plaintext[1];
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
}

void simeckTeaCTR(const uint32_t master_key[], const uint32_t plaintext[], uint32_t ciphertext[]) { 
    int i, idx, simeckrounds = 5, tearounds = 7;
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

    simeckrounds = simeckrounds + psum; // depends on password
    tearounds = tearounds + pmul; // depends on password

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


// MDC-2 hash function using TEA cipher for encryption
void MDC2_Hash(const uint8_t *data, size_t len, uint32_t *hash, const uint32_t *key) {
    uint32_t Pt[2] = {0}; // Plaintext block
    uint32_t Ct[2] = {0}; // Ciphertext block
    uint32_t K1 = 0, K2 = 0;
    size_t i, j;

    for (i = 0; i < len; i++) {
        Pt[i % 2] ^= (uint32_t)data[i] << ((i % 2) * 8);
        if ((i + 1) % 2 == 0) {
	    simeckTeaECB(key, Pt, Ct); 
            K1 ^= Ct[0];
            K2 ^= Ct[1];
            Pt[0] = 0;
            Pt[1] = 0;
        }
    }

    // Final round if there are remaining bytes
    if (len % 2 != 0) {
	simeckTeaECB(key, Pt, Ct); 
        K1 ^= Ct[0];
        K2 ^= Ct[1];
    }

    // Additional post-processing can be done if needed
    for (j = 0; j < 16; j++) {
	K1 += ((K2 & 3) * 0x9e3779b9) ^ ((K2 >> 5) + 0x9e3779b9);
        K2 += ((K1 & 3) * 0x9e3779b9) ^ ((K1 >> 5) + 0x9e3779b9);
    }

    hash[0] = K1;
    hash[1] = K2;
}


// PBKDF2 key derivation function 
void PBKDF2_SIMECKTEA(const char *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t *key, size_t iterations) {
    uint32_t result[2] = {0};
    uint32_t temp[2];
    uint8_t temp_buffer[4 + salt_len + 4];
    size_t i;

    // Iterate through each block to derive the key
    for (i = 1; i <= iterations; i++) {
        // Prepare data for hash computation
        memcpy(temp_buffer, &i, sizeof(uint32_t)); // Block index
        memcpy(temp_buffer + sizeof(uint32_t), salt, salt_len); // Salt
        memcpy(temp_buffer + sizeof(uint32_t) + salt_len, &i, sizeof(uint32_t)); // Block index (again)

        // Perform hash computation
        MDC2_Hash(temp_buffer, sizeof(temp_buffer), temp, (const uint32_t *)password);

        // XOR result with temporary hash
        result[0] ^= temp[0];
        result[1] ^= temp[1];
    }

    // Copy the result to the key
    memcpy(key, result, 2 * sizeof(uint32_t));
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



void PBKDF2(char *passwd, uint32_t *derived_key, size_t iterations) {
    uint32_t strongpwd1[2], strongpwd2[2];
    int pwdlen;

    pwdlen = strlen(passwd);

    /* the PRODUCTSERIALNO and PRODUCTVERSION strings are used to mix the password into a stronger version */
    PBKDF2_SIMECKTEA(passwd, pwdlen, (uint8_t *) PRODUCTSERIALNO, strlen(PRODUCTSERIALNO), strongpwd1, iterations); // output 64 bits = 2 x uint32_t values
    PBKDF2_SIMECKTEA(passwd, pwdlen, (uint8_t *) PRODUCTVERSION, strlen(PRODUCTVERSION), strongpwd2, iterations); // output 64 bits = 2 x uint32_t values

    // copy strong passwords into derived_key 128 bits
    derived_key[0] = strongpwd1[0];
    derived_key[1] = strongpwd1[1];
    derived_key[2] = strongpwd2[0];
    derived_key[3] = strongpwd2[1];												   
}


int main(int argc, char *argv[]) {
    // get input file and out file names
	if (argc != 3) {
		fprintf(stderr, "Usage: %s input-filename output-filename\n", argv[0]);
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

    // Get the modification time from source file
    struct timespec mod_time = statbuf.st_mtim;

    // Convert modification time to string
    char mod_time_str[100];
    get_modification_time_string(&mod_time, mod_time_str, sizeof(mod_time_str));

    // Print the modification time
    print_modification_time(mod_time_str);

    IV = fnv1a_hash(mod_time_str, strlen(mod_time_str));

    // Prepare the times to set on the destination file
    struct timespec new_times[2];
    new_times[0].tv_sec = statbuf.st_atim.tv_sec;  // Access time (seconds)
    new_times[0].tv_nsec = statbuf.st_atim.tv_nsec;  // Access time (nanoseconds)
    new_times[1].tv_sec = statbuf.st_mtim.tv_sec;  // Modification time (seconds)
    new_times[1].tv_nsec = statbuf.st_mtim.tv_nsec;  // Modification time (nanoseconds)

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

    PBKDF2(passwd, derived_key, 65000); 

    psum=0; pmul=1; 

    for (int i = 0; i < 4; i++) {
	psum += derived_key[i]; // overflows by design
	pmul ^= derived_key[i]; // overflows by design
    }

    psum = psum % 10;
    pmul = pmul % 5;
    
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

    int i,len;
    char *ptrdot;
    ptrdot = strrchr(argv[2], '.'); // drop the .extension
    if (ptrdot == NULL) {
	fprintf(stderr, "The output filename is expected to have an .extension suffix\n");
	return -1;
    }
    len = (ptrdot-argv[2]) * sizeof(char);
    IV += fsize + psum + pmul + fnv1a_hash(argv[2], len);
    seed(IV);
    for (i=0; i< psum+pmul; i++) {
	    IV = int64();
    }

    printf("The IV is %lu with this one\n", IV);

    uint32_t plaintext[2], ciphertext[2];
    
    int ret = 8;
    while(ret == 8) {
       if ((ret = fread(plaintext, 1, 8, fp))==0) { // read 64 bits
	        if (ferror(fp)) {
	            perror("fread()");
        	    exit(EXIT_FAILURE);
	        }
        }

        simeckTeaCTR(derived_key, plaintext, ciphertext);

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

    // Set the modification time on the destination file using utimensat
    if (utimensat(AT_FDCWD, argv[2], new_times, 0) != 0) {
        print_error("Failed to set modification time");
    }

    printf("Modification time copied from '%s' to '%s'\n", argv[1], argv[2]);


    return 0;
}
