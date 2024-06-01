# simeck-tea
SIMECK-TEA is a configurable lightweight cipher made of 3 default rounds of SIMECK64 and 5 internal TEA rounds.

This thing is easy on memory, uses 15 rounds and passes dieharder, ent, NIST and AIS31 randomness tests.

It seems suitable for very low power devices. The avalanche property holds already for 3 by 3 rounds.

# NIST standard tests for 3 by 5:
    188/188 tests passed successfully both the analyses.
    0/188 tests did not pass successfully both the analyses.

# AIS31 standard tests for 3 by 5:
    input file A-T0 A-T1 A-T2 A-T3 A-T4 A-T5 B-Step1(T6) B-Step2 B-Step3 B-Step4 B-T8 
    zero.enc PASS 257/257 257/257 257/257 257/257 257/257 PASS PASS PASS PASS 8.00131

# dieharder tests for 3 by 5:
=============================================================================#
            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
=============================================================================#
   rng_name    |           filename             |rands/second|
 file_input_raw|                        zero.enc|  6.41e+07  |
=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
=============================================================================#
   diehard_birthdays|   0|       100|     100|0.42416284|  PASSED  
      diehard_operm5|   0|   1000000|     100|0.90396219|  PASSED  
  diehard_rank_32x32|   0|     40000|     100|0.25671649|  PASSED  
 The file file_input_raw was rewound 1 times
    diehard_rank_6x8|   0|    100000|     100|0.58454057|  PASSED  
 The file file_input_raw was rewound 1 times
   diehard_bitstream|   0|   2097152|     100|0.62287460|  PASSED  
 The file file_input_raw was rewound 2 times
        diehard_opso|   0|   2097152|     100|0.58705602|  PASSED  
 The file file_input_raw was rewound 2 times
        diehard_oqso|   0|   2097152|     100|0.60629047|  PASSED  
 The file file_input_raw was rewound 2 times
         diehard_dna|   0|   2097152|     100|0.66896442|  PASSED  
 The file file_input_raw was rewound 2 times
diehard_count_1s_str|   0|    256000|     100|0.18306207|  PASSED  
 The file file_input_raw was rewound 3 times
diehard_count_1s_byt|   0|    256000|     100|0.23625244|  PASSED  
 The file file_input_raw was rewound 3 times
 diehard_parking_lot|   0|     12000|     100|0.30014525|  PASSED  
 The file file_input_raw was rewound 3 times
    diehard_2dsphere|   2|      8000|     100|0.31811010|  PASSED  
 The file file_input_raw was rewound 3 times
    diehard_3dsphere|   3|      4000|     100|0.06579739|  PASSED  
 The file file_input_raw was rewound 4 times
     diehard_squeeze|   0|    100000|     100|0.65468739|  PASSED  
 The file file_input_raw was rewound 4 times
        diehard_sums|   0|       100|     100|0.61075095|  PASSED  
 The file file_input_raw was rewound 4 times
        diehard_runs|   0|    100000|     100|0.04221968|  PASSED  
        diehard_runs|   0|    100000|     100|0.31551668|  PASSED  
 The file file_input_raw was rewound 4 times
       diehard_craps|   0|    200000|     100|0.30262067|  PASSED  
       diehard_craps|   0|    200000|     100|0.92577372|  PASSED  
 The file file_input_raw was rewound 12 times
 marsaglia_tsang_gcd|   0|  10000000|     100|0.93574799|  PASSED  
 marsaglia_tsang_gcd|   0|  10000000|     100|0.58564469|  PASSED  
 The file file_input_raw was rewound 12 times
         sts_monobit|   1|    100000|     100|0.27473908|  PASSED  
 The file file_input_raw was rewound 12 times
            sts_runs|   2|    100000|     100|0.97100310|  PASSED  
 The file file_input_raw was rewound 12 times
          sts_serial|   1|    100000|     100|0.78060761|  PASSED  
          sts_serial|   2|    100000|     100|0.87481010|  PASSED  
          sts_serial|   3|    100000|     100|0.62392051|  PASSED  
          sts_serial|   3|    100000|     100|0.33627152|  PASSED  
          sts_serial|   4|    100000|     100|0.25217966|  PASSED  
          sts_serial|   4|    100000|     100|0.67726204|  PASSED  
          sts_serial|   5|    100000|     100|0.77965793|  PASSED  
          sts_serial|   5|    100000|     100|0.35707848|  PASSED  
          sts_serial|   6|    100000|     100|0.31533370|  PASSED  
          sts_serial|   6|    100000|     100|0.20426429|  PASSED  
          sts_serial|   7|    100000|     100|0.73882998|  PASSED  
          sts_serial|   7|    100000|     100|0.64287396|  PASSED  
          sts_serial|   8|    100000|     100|0.66937147|  PASSED  
          sts_serial|   8|    100000|     100|0.22880765|  PASSED  
          sts_serial|   9|    100000|     100|0.81315068|  PASSED  
          sts_serial|   9|    100000|     100|0.99449761|  PASSED  
          sts_serial|  10|    100000|     100|0.30705681|  PASSED  
          sts_serial|  10|    100000|     100|0.15096944|  PASSED  
          sts_serial|  11|    100000|     100|0.17284869|  PASSED  
          sts_serial|  11|    100000|     100|0.93150134|  PASSED  
          sts_serial|  12|    100000|     100|0.51815475|  PASSED  
          sts_serial|  12|    100000|     100|0.00284038|   WEAK   
          sts_serial|  13|    100000|     100|0.93319263|  PASSED  
          sts_serial|  13|    100000|     100|0.98569632|  PASSED  
          sts_serial|  14|    100000|     100|0.53178727|  PASSED  
          sts_serial|  14|    100000|     100|0.58472140|  PASSED  
          sts_serial|  15|    100000|     100|0.22798398|  PASSED  
          sts_serial|  15|    100000|     100|0.14783685|  PASSED  
          sts_serial|  16|    100000|     100|0.05660432|  PASSED  
          sts_serial|  16|    100000|     100|0.56938154|  PASSED  
 The file file_input_raw was rewound 12 times
         rgb_bitdist|   1|    100000|     100|0.06120235|  PASSED  
 The file file_input_raw was rewound 12 times
         rgb_bitdist|   2|    100000|     100|0.04874390|  PASSED  
 The file file_input_raw was rewound 12 times
         rgb_bitdist|   3|    100000|     100|0.47188762|  PASSED  
 The file file_input_raw was rewound 12 times
         rgb_bitdist|   4|    100000|     100|0.69441854|  PASSED  
 The file file_input_raw was rewound 13 times
         rgb_bitdist|   5|    100000|     100|0.48927794|  PASSED  
 The file file_input_raw was rewound 13 times
         rgb_bitdist|   6|    100000|     100|0.26050902|  PASSED  
 The file file_input_raw was rewound 14 times
         rgb_bitdist|   7|    100000|     100|0.43858946|  PASSED  
 The file file_input_raw was rewound 14 times
         rgb_bitdist|   8|    100000|     100|0.76606832|  PASSED  
 The file file_input_raw was rewound 15 times
         rgb_bitdist|   9|    100000|     100|0.64594597|  PASSED  
 The file file_input_raw was rewound 16 times
         rgb_bitdist|  10|    100000|     100|0.85587250|  PASSED  
 The file file_input_raw was rewound 17 times
         rgb_bitdist|  11|    100000|     100|0.33196892|  PASSED  
 The file file_input_raw was rewound 18 times
         rgb_bitdist|  12|    100000|     100|0.31276352|  PASSED  
 The file file_input_raw was rewound 18 times
rgb_minimum_distance|   2|     10000|    1000|0.99099628|  PASSED  
 The file file_input_raw was rewound 18 times
rgb_minimum_distance|   3|     10000|    1000|0.87693387|  PASSED  
 The file file_input_raw was rewound 18 times
rgb_minimum_distance|   4|     10000|    1000|0.94344463|  PASSED  
 The file file_input_raw was rewound 18 times
rgb_minimum_distance|   5|     10000|    1000|0.05957463|  PASSED  
 The file file_input_raw was rewound 18 times
    rgb_permutations|   2|    100000|     100|0.06182587|  PASSED  
 The file file_input_raw was rewound 18 times
    rgb_permutations|   3|    100000|     100|0.50339373|  PASSED  
 The file file_input_raw was rewound 18 times
    rgb_permutations|   4|    100000|     100|0.18368749|  PASSED  
 The file file_input_raw was rewound 19 times
    rgb_permutations|   5|    100000|     100|0.64974319|  PASSED  
 The file file_input_raw was rewound 19 times
      rgb_lagged_sum|   0|   1000000|     100|0.84182767|  PASSED  
 The file file_input_raw was rewound 20 times
      rgb_lagged_sum|   1|   1000000|     100|0.77306122|  PASSED  
 The file file_input_raw was rewound 21 times
      rgb_lagged_sum|   2|   1000000|     100|0.26548518|  PASSED  
 The file file_input_raw was rewound 22 times
      rgb_lagged_sum|   3|   1000000|     100|0.49560134|  PASSED  
 The file file_input_raw was rewound 24 times
      rgb_lagged_sum|   4|   1000000|     100|0.98957276|  PASSED  
 The file file_input_raw was rewound 26 times
      rgb_lagged_sum|   5|   1000000|     100|0.99078086|  PASSED  
 The file file_input_raw was rewound 29 times
      rgb_lagged_sum|   6|   1000000|     100|0.69429453|  PASSED  
 The file file_input_raw was rewound 32 times
      rgb_lagged_sum|   7|   1000000|     100|0.91225129|  PASSED  
 The file file_input_raw was rewound 35 times
      rgb_lagged_sum|   8|   1000000|     100|0.86157646|  PASSED  
 The file file_input_raw was rewound 39 times
      rgb_lagged_sum|   9|   1000000|     100|0.45669242|  PASSED  
 The file file_input_raw was rewound 43 times
      rgb_lagged_sum|  10|   1000000|     100|0.53995334|  PASSED  
 The file file_input_raw was rewound 48 times
      rgb_lagged_sum|  11|   1000000|     100|0.85364121|  PASSED  
 The file file_input_raw was rewound 53 times
      rgb_lagged_sum|  12|   1000000|     100|0.85653315|  PASSED  
 The file file_input_raw was rewound 58 times
      rgb_lagged_sum|  13|   1000000|     100|0.92763858|  PASSED  
 The file file_input_raw was rewound 63 times
      rgb_lagged_sum|  14|   1000000|     100|0.23304005|  PASSED  
 The file file_input_raw was rewound 69 times
      rgb_lagged_sum|  15|   1000000|     100|0.34737602|  PASSED  
 The file file_input_raw was rewound 76 times
      rgb_lagged_sum|  16|   1000000|     100|0.70433355|  PASSED  
 The file file_input_raw was rewound 82 times
      rgb_lagged_sum|  17|   1000000|     100|0.77575856|  PASSED  
 The file file_input_raw was rewound 89 times
      rgb_lagged_sum|  18|   1000000|     100|0.97393742|  PASSED  
 The file file_input_raw was rewound 97 times
      rgb_lagged_sum|  19|   1000000|     100|0.71803031|  PASSED  
 The file file_input_raw was rewound 105 times
      rgb_lagged_sum|  20|   1000000|     100|0.52507214|  PASSED  
 The file file_input_raw was rewound 113 times
      rgb_lagged_sum|  21|   1000000|     100|0.79800690|  PASSED  
 The file file_input_raw was rewound 121 times
      rgb_lagged_sum|  22|   1000000|     100|0.76631081|  PASSED  
 The file file_input_raw was rewound 130 times
      rgb_lagged_sum|  23|   1000000|     100|0.61365595|  PASSED  
 The file file_input_raw was rewound 140 times
      rgb_lagged_sum|  24|   1000000|     100|0.91478314|  PASSED  
 The file file_input_raw was rewound 149 times
      rgb_lagged_sum|  25|   1000000|     100|0.29321969|  PASSED  
 The file file_input_raw was rewound 159 times
      rgb_lagged_sum|  26|   1000000|     100|0.99945460|   WEAK   
 The file file_input_raw was rewound 170 times
      rgb_lagged_sum|  27|   1000000|     100|0.42853747|  PASSED  
 The file file_input_raw was rewound 181 times
      rgb_lagged_sum|  28|   1000000|     100|0.87858278|  PASSED  
 The file file_input_raw was rewound 192 times
      rgb_lagged_sum|  29|   1000000|     100|0.67446538|  PASSED  
 The file file_input_raw was rewound 203 times
      rgb_lagged_sum|  30|   1000000|     100|0.59183947|  PASSED  
 The file file_input_raw was rewound 215 times
      rgb_lagged_sum|  31|   1000000|     100|0.00111843|   WEAK   
 The file file_input_raw was rewound 228 times
      rgb_lagged_sum|  32|   1000000|     100|0.65029784|  PASSED  
 The file file_input_raw was rewound 228 times
     rgb_kstest_test|   0|     10000|    1000|0.09243024|  PASSED  
 The file file_input_raw was rewound 228 times
     dab_bytedistrib|   0|  51200000|       1|0.32415195|  PASSED  
 The file file_input_raw was rewound 228 times
             dab_dct| 256|     50000|       1|0.61544250|  PASSED  
Preparing to run test 207.  ntuple = 0
 The file file_input_raw was rewound 229 times
        dab_filltree|  32|  15000000|       1|0.95225619|  PASSED  
        dab_filltree|  32|  15000000|       1|0.51336534|  PASSED  
Preparing to run test 208.  ntuple = 0
 The file file_input_raw was rewound 229 times
       dab_filltree2|   0|   5000000|       1|0.56890750|  PASSED  
       dab_filltree2|   1|   5000000|       1|0.21390197|  PASSED  
Preparing to run test 209.  ntuple = 0
 The file file_input_raw was rewound 229 times
        dab_monobit2|  12|  65000000|       1|0.51619264|  PASSED  

