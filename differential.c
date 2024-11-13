#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
                    
#define MAX_TRIALS  10000000 //4294967296  //this is now 2^32 not 10000000
#define WORDSIZE 32
#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)


// Function pointer type for computing differences
typedef void (*compute_diff_func)(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]);

void SimeckTeaECB(const uint32_t master_key[], const uint32_t plaintext[], uint32_t ciphertext[]) {
    int idx, simeckrounds = 3, tearounds = 5; // Adjust as needed 3 by 5
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
        // Simeck round
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

        // Rotate the LFSR of keys
        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;

        // TEA-like rounds
        uint32_t y = ciphertext[0], z = ciphertext[1], sum = 0, delta = 0x9e3779b9;

        while (tearounds-- > 0) {
            sum += delta;
            y += ((z << 4) + keys[0]) ^ (z + sum) ^ ((z >> 5) + keys[1]);
            z += ((y << 4) + keys[2]) ^ (y + sum) ^ ((y >> 5) + keys[3]);
        }

        ciphertext[0] = y;
        ciphertext[1] = z;
    }
}

void SimeckTeaECBDecrypt(const uint32_t master_key[], const uint32_t ciphertext[], uint32_t plaintext[]) {
    int idx, simeckrounds = 1, tearounds = 1; // Adjust as needed
    uint32_t keys[4] = {
        master_key[0],
        master_key[1],
        master_key[2],
        master_key[3],
    };
    uint32_t constant = 0xFFFFFFFC;
    uint64_t sequence = 0x938BCA3083F;

    plaintext[0] = ciphertext[0];
    plaintext[1] = ciphertext[1];
    uint32_t temp;

    // Key rotation buffer for reverse LFSR rotation
    uint32_t lfsr_keys[simeckrounds + 1][4];
    for (int i = 0; i < 4; i++) {
        lfsr_keys[0][i] = keys[i];
    }

    // Forward key expansion and LFSR simulation
    for (idx = 0; idx < simeckrounds; idx++) {
        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        // Store the current keys state for reverse usage
        for (int i = 0; i < 4; i++) {
            lfsr_keys[idx + 1][i] = keys[i];
        }

        // Rotate the LFSR of keys for forward direction
        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;
    }

    for (idx = simeckrounds - 1; idx >= 0; idx--) {
        uint32_t y = plaintext[0], z = plaintext[1], delta = 0x9e3779b9;
        uint32_t sum = delta * tearounds;

        // TEA-like rounds (reverse)
        while (sum != 0) {
            z -= ((y << 4) + lfsr_keys[idx + 1][2]) ^ (y + sum) ^ ((y >> 5) + lfsr_keys[idx + 1][3]);
            y -= ((z << 4) + lfsr_keys[idx + 1][0]) ^ (z + sum) ^ ((z >> 5) + lfsr_keys[idx + 1][1]);
            sum -= delta;
        }

        plaintext[0] = y;
        plaintext[1] = z;

        // Reverse Simeck round
        ROUND64(
            constant,
            lfsr_keys[idx + 1][1],
            lfsr_keys[idx + 1][0],
            temp
        );

        ROUND64(
            lfsr_keys[idx + 1][0],
            plaintext[1],
            plaintext[0],
            temp
        );
    }
}



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
void compute_hamming_distance(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = hamming_distance(v1[0], v2[0]);
    result[1] = hamming_distance(v1[1], v2[1]);
}

// Function to compute additive difference modulo 2^32 for each 32-bit word
void compute_additive_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] - v2[0]) & 0xFFFFFFFF; // Modulo 2^32
    result[1] = (v1[1] - v2[1]) & 0xFFFFFFFF;
}

void compute_modular_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] - v2[0]) % 0xFFFFFFFF;
    result[1] = (v1[1] - v2[1]) % 0xFFFFFFFF;
}

void compute_signeddifferential_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = v1[0] - v2[0];
    result[1] = v1[1] - v2[1];
}


void compute_OR_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] | v2[0]);
    result[1] = (v1[1] | v2[1]);
}

void compute_AND_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = (v1[0] & v2[0]);
    result[1] = (v1[1] & v2[1]);
}


// Function to compute Hamming distance, which is effectively the same as bitwise Levenshtein distance for fixed-size blocks
int bitwise_levenshtein_distance(uint32_t a, uint32_t b) {
    uint32_t diff = a ^ b; // XOR to find differing bits
    int distance = 0;
    
    // Count the number of set bits in `diff`
    while (diff) {
        distance += diff & 1;
        diff >>= 1;
    }
    return distance;
}

// Modified compute_difference function using "bitwise Levenshtein distance"
void compute_levenshtein_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    result[0] = bitwise_levenshtein_distance(v1[0], v2[0]);
    result[1] = bitwise_levenshtein_distance(v1[1], v2[1]);
}

// Rotate left function
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Rotate right function
uint32_t rotate_right(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// Function to rotate a block by a given number of bits
uint32_t rotate_block(uint32_t block, int rotation) {
    block = LROT32(block, rotation);
    return block;
}


// Compute rotational "difference" by checking rotational equivalence
void compute_rotational_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    int r;
    r = rand()%32;
    rotate_left(v1[0], r); //..fixed bits here like 1, repeat until 32
    r = rand()%32;
    rotate_right(v1[1], r);
    result[0] = v1[0] - v2[0];
    result[1] = v1[1] - v2[1];
}
	
// Compute rotational "difference" left by checking rotational equivalence
void compute_rotateleft_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    int r;
    r = rand()%32;
    rotate_left(v1[0], r);
    r = rand()%32;
    rotate_left(v1[1], r);
    result[0] = v1[0] ^ v2[0];
    result[1] = v1[1] ^ v2[1];
}

// Compute rotational "difference" right by checking rotational equivalence
void compute_rotateright_difference(uint32_t result[2], const uint32_t v1[2], const uint32_t v2[2]) {
    int r;
    r = rand()%32;
    rotate_right(v1[0], r);
    r = rand()%32;
    rotate_right(v1[1], r);

    result[0] = v1[0] ^ v2[0];
    result[1] = v1[1] ^ v2[1];
/*
    
	for (int r = 1; r < 32; r++) {
        if (rotate_right(v1[0], r) == v2[0] && rotate_right(v1[1], r) == v2[1]) {
            result[0] = r;
            result[1] = r;
            return; // Rotational pair found with rotation `r`
        }
    }
  //  result[0] = 0;
//    result[1] = 0;
    result[0] = v1[0] ^ v2[0];
    result[1] = v1[1] ^ v2[1];
*/
}

// Additional function to check bitwise balances in results
int is_balanced(uint32_t result[2]) {
    uint32_t xored = result[0] ^ result[1];
    int count = __builtin_popcount(xored); // GCC built-in function for Hamming weight
    return count == WORDSIZE / 2; // For balanced, half of bits should differ
}



// Hash table entry structure to store differences
typedef struct {
    uint32_t diff1;  // first 32-bit word of the difference
    uint32_t diff2;  // second 32-bit word of the difference
    int count;       // number of occurrences
} DifferenceEntry;

// Hash table size
#define TABLE_SIZE 10000007 //4294967311 // .. 296 is 2^32//43000019 //10000007 // Prime number for hash table size
DifferenceEntry *hash_table; //hash_table[TABLE_SIZE];

// Hash function for the differences
unsigned int hash_function(uint32_t diff1, uint32_t diff2) {
    return (diff1 * 31 + diff2) % TABLE_SIZE;
    //return (diff1 * 2654435761 + diff2 * 0x9e3779b9) % TABLE_SIZE;
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
        fprintf(stderr, "Available types: xor, hamming, additive, modular, signdiff, or, and, levenshtein, rotational, rotleft, rotright\n");
        return 1;
    }

    hash_table = (DifferenceEntry *) malloc(sizeof(DifferenceEntry) * TABLE_SIZE);
    if (hash_table == NULL) {
	perror("malloc");
	return -1;
    } else printf("Allocated table for %lu entries.\n", TABLE_SIZE);

    // Select the appropriate compute_difference function based on the command line argument
    compute_diff_func compute_difference;
    if (strcmp(argv[1], "xor") == 0) {
        compute_difference = compute_xor_difference;
    } else if (strcmp(argv[1], "hamming") == 0) {
        compute_difference = compute_hamming_distance;
    } else if (strcmp(argv[1], "additive") == 0) {
        compute_difference = compute_additive_difference;
    } else if (strcmp(argv[1], "modular") == 0) {
        compute_difference = compute_modular_difference;
    } else if (strcmp(argv[1], "signdiff") == 0) {
        compute_difference = compute_signeddifferential_difference;
    } else if (strcmp(argv[1], "or") == 0) {
        compute_difference = compute_OR_difference;
    } else if (strcmp(argv[1], "and") == 0) {
        compute_difference = compute_AND_difference;
    } else if (strcmp(argv[1], "levenshtein") == 0) {
        compute_difference = compute_levenshtein_difference;
    } else if (strcmp(argv[1], "rotleft") == 0) {
        compute_difference = compute_rotateleft_difference;
    } else if (strcmp(argv[1], "rotright") == 0) {
        compute_difference = compute_rotateright_difference;
    } else if (strcmp(argv[1], "rotational") == 0) {
        compute_difference = compute_rotational_difference;
	
    } else {
        fprintf(stderr, "Invalid differential type specified!\n");
        return 1;
    }

    // Seed random number generator
    srand(time(NULL));

    // Define key for TEA encryption (random constant key used here)
    uint32_t key[4] = {((uint32_t)rand() << 16) | (uint32_t)rand(), ((uint32_t)rand() << 16) | (uint32_t)rand(), ((uint32_t)rand() << 16) | (uint32_t)rand(), ((uint32_t)rand() << 16) | (uint32_t)rand()};

    // Number of rounds (TEA typically uses 32 rounds)
    int rounds = 32;

    // Input difference ΔP (chosen difference for the attack)
    uint32_t input_diff[2] = {((uint32_t)rand() << 16) | (uint32_t)rand(), ((uint32_t)rand() << 16) | (uint32_t)rand()};

    // Arrays to hold plaintext pairs and ciphertext pairs
    uint32_t plaintext1[2], plaintext2[2], ciphertext1[2], ciphertext2[2];
    uint32_t output_diff[2];

    // Number of trials (e.g., 1 million trials)
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

	SimeckTeaECB(key, plaintext1, ciphertext1);
	SimeckTeaECB(key, plaintext2, ciphertext2);

//        TEA_encrypt(ciphertext1, key, rounds);
//        TEA_encrypt(ciphertext2, key, rounds);

        // Compute the output difference ΔC using the selected function
        compute_difference(output_diff, ciphertext1, ciphertext2);

        // Insert the full 64-bit output difference into the hash table
        insert_or_increment(output_diff[0], output_diff[1]);

        // Optionally, print progress every 100000 trials
        if (trial % 100000 == 0 && trial != 0) {
            printf("Progress: %d trials completed...\n", trial);
        } else if ((trial % 1000 == 0) && (trial != 0) && (trial > num_trials - 100000) ) {
            printf("Progress: %d trials completed...\n", trial);
        }


    }

    printf("Now finding the most frequent difference:\n");
    
    // Find the most frequent difference
    DifferenceEntry best_trail = find_most_frequent();

    // Print the result
    printf("Most frequent output difference: (%u, %u) occurs %d times => %f\%\n", best_trail.diff1, best_trail.diff2, best_trail.count,
		    100.0*best_trail.count/num_trials);

    return 0;
}

