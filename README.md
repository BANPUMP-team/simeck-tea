# simeck-tea
SIMECK-TEA is a configurable lightweight cipher made of 5 default rounds of SIMECK64 and 5 internal TEA rounds.

This thing is easy on memory, uses 25 rounds and passes dieharder, ent, NIST and AIS31 randomness tests.

It seems suitable for very low power devices: 3 by 5 but also 5 by 4 rounds do produce random data. The avalanche property holds already for 3 by 3 rounds, which seem little for a 128 bit key.


