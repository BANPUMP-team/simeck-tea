#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define MAX_TRIALS 10000000

// Function pointer type for computing differences
typedef void (*compute_diff_func)(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]);

// XOR-based difference computation
void compute_xor_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = v1[0] ^ v2[0];
    result[1] = v1[1] ^ v2[1];
}

// Function to compute Hamming distance
int hamming_distance(uint32_t a, uint32_t b) {
    uint32_t x = a ^ b;
    int distance = 0;
    while (x) {
        distance += x & 1;
        x >>= 1;
    }
    return distance;
}

// Bitwise Levenshtein distance
void compute_bitwise_levenshtein_distance(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = hamming_distance(v1[0], v2[0]);
    result[1] = hamming_distance(v1[1], v2[1]);
}

// Function to compute additive difference modulo 2^32 for each 32-bit word
void compute_additive_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] - v2[0]) & 0xFFFFFFFF; // Modulo 2^32
    result[1] = (v1[1] - v2[1]) & 0xFFFFFFFF;
}

// Function to compute absolute difference
void compute_absolute_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = abs((int32_t)v1[0] - (int32_t)v2[0]);
    result[1] = abs((int32_t)v1[1] - (int32_t)v2[1]);
}

// Function to compute the average difference
void compute_average_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] + v2[0]) / 2;
    result[1] = (v1[1] + v2[1]) / 2;
}

// Function to compute the multiplicative difference
void compute_multiplicative_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] * v2[0]) & 0xFFFFFFFF;
    result[1] = (v1[1] * v2[1]) & 0xFFFFFFFF;
}

// Function to compute the bitwise AND difference
void compute_bitwise_and_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = v1[0] & v2[0];
    result[1] = v1[1] & v2[1];
}

// Function to compute the bitwise OR difference
void compute_bitwise_or_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = v1[0] | v2[0];
    result[1] = v1[1] | v2[1];
}

// Function to compute the bitwise NOT difference
void compute_bitwise_not_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = ~v1[0];
    result[1] = ~v1[1];
}

// Function to compute the maximum difference
void compute_max_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] > v2[0]) ? v1[0] : v2[0];
    result[1] = (v1[1] > v2[1]) ? v1[1] : v2[1];
}

// Hash table entry structure to store differences
typedef struct {
    uint32_t diff1;  // first 32-bit word of the difference
    uint32_t diff2;  // second 32-bit word of the difference
    int count;       // number of occurrences
} DifferenceEntry;

// Hash table size
#define TABLE_SIZE 10000003 // Prime number for hash table size
DifferenceEntry hash_table[TABLE_SIZE];

// Hash function for the differences
unsigned int hash_function(uint32_t diff1, uint32_t diff2) {
    return (diff1 * 31 + diff2) % TABLE_SIZE;
}

// Insert or increment the count for a difference in the hash table
void insert_or_increment(uint32_t diff1, uint32_t diff2) {
    unsigned int index = hash_function(diff1, diff2);
    while (hash_table[index].count > 0) {
        if (hash_table[index].diff1 == diff1 && hash_table[index].diff2 == diff2) {
            hash_table[index].count++;
            return;
        }
        index = (index + 1) % TABLE_SIZE;
    }
    hash_table[index].diff1 = diff1;
    hash_table[index].diff2 = diff2;
    hash_table[index].count = 1;
}

// Find the most frequent difference
DifferenceEntry find_most_frequent() {
    DifferenceEntry best = {0, 0, 0};
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (hash_table[i].count > best.count) {
            best = hash_table[i];
        }
    }
    return best;
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <differential_type>\n", argv[0]);
        fprintf(stderr, "Available types: xor, hamming, additive, abs, avg, mul, and, or, not, max\n");
        return 1;
    }

    // Select the appropriate compute_difference function based on the command line argument
    compute_diff_func compute_difference;
    if (strcmp(argv[1], "xor") == 0) {
        compute_difference = compute_xor_difference;
    } else if (strcmp(argv[1], "hamming") == 0) {
        compute_difference = compute_bitwise_levenshtein_distance;
    } else if (strcmp(argv[1], "additive") == 0) {
        compute_difference = compute_additive_difference;
    } else if (strcmp(argv[1], "abs") == 0) {
        compute_difference = compute_absolute_difference;
    } else if (strcmp(argv[1], "avg") == 0) {
        compute_difference = compute_average_difference;
    } else if (strcmp(argv[1], "mul") == 0) {
        compute_difference = compute_multiplicative_difference;
    } else if (strcmp(argv[1], "and") == 0) {
        compute_difference = compute_bitwise_and_difference;
    } else if (strcmp(argv[1], "or") == 0) {
        compute_difference = compute_bitwise_or_difference;
    } else if (strcmp(argv[1], "not") == 0) {
        compute_difference = compute_bitwise_not_difference;
    } else if (strcmp(argv[1], "max") == 0) {
        compute_difference = compute_max_difference;
    } else {
        fprintf(stderr, "Invalid differential type specified!\n");
        return 1;
    }

    // Seed random number generator
    srand(time(NULL));

    // Define key for TEA encryption (random constant key used here)
    uint32_t key[4] = {
        ((uint32_t)rand() << 16) | (uint32_t)rand(),
        ((uint32_t)rand() << 16) | (uint32_t)rand(),
        ((uint32_t)rand() << 16) | (uint32_t)rand(),
        ((uint32_t)rand() << 16) | (uint32_t)rand()
    };

    // Number of rounds (TEA typically uses 32 rounds)
    int rounds = 32;

    // Input difference ΔP (chosen difference for the attack)
    uint32_t input_diff[2] = {
        ((uint32_t)rand() << 16) | (uint32_t)rand(),
        ((uint32_t)rand() << 16) | (uint32_t)rand()
    };

    // Arrays to hold plaintext pairs and ciphertext pairs
    uint32_t plaintext1[2], plaintext2[2], ciphertext1[2], ciphertext2[2];
    uint32_t output_diff[2];

    // Number of trials (e.g., 10 million trials)
    int num_trials = MAX_TRIALS;

    printf("Starting differential cryptanalysis over %d trials and %d rounds...\n", num_trials, rounds);

    // Main loop to test multiple plaintext pairs
    for (int trial = 0; trial < num_trials; trial++) {
        // Generate a random plaintext pair
        plaintext1[0] = ((uint32_t)rand() << 16) | (uint32_t)rand();
        plaintext1[1] = ((uint32_t)rand() << 16) | (uint32_t)rand();
        
        // Apply input difference to get the second plaintext
        plaintext2[0] = plaintext1[0] ^ input_diff[0];
        plaintext2[1] = plaintext1[1] ^ input_diff[1];

        // Encrypt both plaintexts
        ciphertext1[0] = plaintext1[0];
        ciphertext1[1] = plaintext1[1];
        ciphertext2[0] = plaintext2[0];
        ciphertext2[1] = plaintext2[1];

        TEA_encrypt(ciphertext1, key, rounds);
        TEA_encrypt(ciphertext2, key, rounds);

        // Compute the output difference ΔC using the selected function
        compute_difference(output_diff, ciphertext1, ciphertext2);

        // Insert the full 64-bit output difference into the hash table
        insert_or_increment(output_diff[0], output_diff[1]);

        // Optionally, print progress every 100000 trials
        if (trial % 100000 == 0 && trial != 0) {
            printf("Progress: %d trials completed...\n", trial);
        }
    }

    // Find the most frequent difference
    DifferenceEntry best_trail = find_most_frequent();

    // Print the result
    printf("Most frequent output difference: (%u, %u) occurs %d times\n", best_trail.diff1, best_trail.diff2, best_trail.count);

    return 0;
}

