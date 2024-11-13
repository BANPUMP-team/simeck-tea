#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

#define DELTA 0x9e3779b9    // TEA magic constant
//#define NUM_PAIRS  1000000000 // Number of plaintext-ciphertext pairs to use
#define NUM_PAIRS  4294967295
//#define NUM_PAIRS  4294967296 //= 2^32 pairs

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

void SimeckTeaECB(const uint32_t master_key[], const uint32_t plaintext[], uint32_t ciphertext[]) {
    int idx, simeckrounds = 3, tearounds = 5;  // 3 by 5
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
        ROUND64(keys[0], ciphertext[1], ciphertext[0], temp);
        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        ROUND64(constant, keys[1], keys[0], temp);

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;

        uint32_t y = ciphertext[0], z = ciphertext[1], sum = 0, delta = 0x9e3779b9;
        int tea_rounds = tearounds;
        while (tea_rounds-- > 0) {
            sum += delta;
            y += ((z << 4) + keys[0]) ^ (z + sum) ^ ((z >> 5) + keys[1]);
            z += ((y << 4) + keys[2]) ^ (y + sum) ^ ((y >> 5) + keys[3]);
        }

        ciphertext[0] = y;
        ciphertext[1] = z;
    }
}

void generate_plaintexts(uint32_t *p0, uint32_t *p1, long int num_pairs) {
    for (uint32_t i = 0; i < num_pairs; i++) {
        p0[i] = rand();
        p1[i] = rand();
    }
}

long int calculate_bias(uint32_t *plain0, uint32_t *plain1, uint32_t *cipher0, uint32_t *cipher1, long int num_pairs, int guess_key) {
    long int count = 0;
    for (uint32_t i = 0; i < num_pairs; i++) {
        int p_pos = rand() % 32;
        int c_pos = rand() % 32;
        int k_pos = rand() % 8;

        int p_bit = (plain0[i] >> p_pos) & 1;
        int c_bit = (cipher1[i] >> c_pos) & 1;
        int key_guess_bit = (guess_key >> k_pos) & 1;

        if ((p_bit ^ c_bit) == key_guess_bit) {
            count++;
        }
    }
    return count - (num_pairs / 2);
}

void linear_cryptanalysis_simeckt(uint32_t const key[4]) {
    int fd_plain0 = open("plain0.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int fd_plain1 = open("plain1.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int fd_cipher0 = open("cipher0.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int fd_cipher1 = open("cipher1.dat", O_RDWR | O_CREAT | O_TRUNC, 0600);

    ftruncate(fd_plain0, NUM_PAIRS * sizeof(uint32_t));
    ftruncate(fd_plain1, NUM_PAIRS * sizeof(uint32_t));
    ftruncate(fd_cipher0, NUM_PAIRS * sizeof(uint32_t));
    ftruncate(fd_cipher1, NUM_PAIRS * sizeof(uint32_t));

    uint32_t *plain0 = (uint32_t *) mmap(NULL, NUM_PAIRS * sizeof(uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd_plain0, 0);
    uint32_t *plain1 = (uint32_t *) mmap(NULL, NUM_PAIRS * sizeof(uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd_plain1, 0);
    uint32_t *cipher0 = (uint32_t *) mmap(NULL, NUM_PAIRS * sizeof(uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd_cipher0, 0);
    uint32_t *cipher1 = (uint32_t *) mmap(NULL, NUM_PAIRS * sizeof(uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd_cipher1, 0);

    generate_plaintexts(plain0, plain1, NUM_PAIRS);

    for (uint32_t i = 0; i < NUM_PAIRS; i++) {
        uint32_t plaintext[2] = {plain0[i], plain1[i]};
        uint32_t ciphertext[2];
        SimeckTeaECB(key, plaintext, ciphertext);
        cipher0[i] = ciphertext[0];
        cipher1[i] = ciphertext[1];
    }

    int count_bias[256] = {0};
    for (int guess_key = 0; guess_key < 256; guess_key++) {
        count_bias[guess_key] = calculate_bias(plain0, plain1, cipher0, cipher1, NUM_PAIRS, guess_key);
    }

    int best_guess = 0;
    int max_bias = 0;
    for (uint32_t i = 0; i < 256; i++) {
        if (count_bias[i] > max_bias) {
            max_bias = count_bias[i];
            best_guess = i;
        }
    }

    printf("Best key guess: 0x%02x with bias: %f%%\n", best_guess, 100.0 * max_bias / NUM_PAIRS);

    munmap(plain0, NUM_PAIRS * sizeof(uint32_t));
    munmap(plain1, NUM_PAIRS * sizeof(uint32_t));
    munmap(cipher0, NUM_PAIRS * sizeof(uint32_t));
    munmap(cipher1, NUM_PAIRS * sizeof(uint32_t));

    close(fd_plain0);
    close(fd_plain1);
    close(fd_cipher0);
    close(fd_cipher1);
    unlink("plain0.dat");
    unlink("plain1.dat");
    unlink("cipher0.dat");
    unlink("cipher1.dat");
}

int main() {
    srand(time(NULL));

    uint32_t key[4] = {rand() & 0xFF, 0, 0, 0};

    printf("Performing linear cryptanalysis on SIMECK-T...\n");
    linear_cryptanalysis_simeckt(key);

    return 0;
}

