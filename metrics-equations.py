#!/usr/bin/python

import argparse
import re
from pathlib import Path

import collections
import math

import statistics
import numpy 

def argparse_equations_type(arg_value, pat=re.compile(r"^call_([a-z0-9_]+)$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError("invalid value, <" + arg_value + "> must in the format of call_XXX")
    return arg_value


def call_eq8_freq(data):
    freqs = collections.Counter(data)
    return freqs

def call_eq8(cleartextdata, crypttextdata):
    freqs_ct = call_eq8_freq(cleartextdata)
    freqs_xt = call_eq8_freq(crypttextdata)

    s = 0
    for k in set(freqs_ct) | set(freqs_xt):
        s += ((freqs_ct.get(k, 0) - freqs_xt.get(k, 0))**2 / 256)
        
    return s

def call_eq9(cleartextdata, crypttextdata):
    s = 0
    l1 = len(cleartextdata)
    l2 = len(crypttextdata)

    for x, y in zip(cleartextdata, crypttextdata): 
        s += (x - y)**2

    # return s / (l1 * l2)
    return s / l1

def call_eq10(cleartextdata, crypttextdata):
    mse = call_eq9(cleartextdata, crypttextdata)

    # TODO: could be max of crypttextdata instead
    # imax = max(cleartextdata)
    imax = max(crypttextdata)

    return 10 * math.log2(imax**2 / mse) if imax > 0 else 0

def luminance(data):
    return sum(data) / len(data)

def call_eq11(cleartextdata, crypttextdata):
    # TODO: don't know what D1 and D2 are
    D1 = 1
    D2 = 1

    up = luminance(cleartextdata)
    uc = luminance(crypttextdata)

    sigmap = statistics.stdev(cleartextdata)
    sigmac = statistics.stdev(cleartextdata)

    # TODO: don't know what sigmapc in (2 * sigmapc + D1) means, elected to put sigmap
    return ((2 * up * uc + D1) * (2 * sigmap + D1)) / ((uc * uc + up * up + D1) * (sigmap * sigmap + sigmac * sigmac + D2))

def call_eq12(cleartextdata, crypttextdata):
    up = luminance(cleartextdata)
    uc = luminance(crypttextdata)

    s = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        s+= (x - up) * (y - uc)
    
    arrp = numpy.array(cleartextdata)
    arrc = numpy.array(crypttextdata)

    varp = numpy.var(arrp)
    varc = numpy.var(arrc)

    if varp == 0 or varc == 0:
        return 0
    
    # TODO: equation is unusable because of input P always 0
    # return (s / math.sqrt(varp * varc) / (len(cleartextdata) * len(crypttextdata)))
    return (s / math.sqrt(varp * varc)) / len(cleartextdata)

def call_eq13(cleartextdata, crypttextdata):
    s = 0
    for x, y in zip(cleartextdata, crypttextdata):
        s+= abs(x - y)

    print(s)
    # return (s / (len(cleartextdata) * len(crypttextdata)))
    return s / len(cleartextdata)

def call_eq14(cleartextdata, crypttextdata):
    s = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        s+= abs(x - y)

    s2 = sum(cleartextdata)
    if s2 == 0:
        return 0
    
    # TODO: equation is unusable because of input P always 0
    return (s / s2)

def call_eq15(cleartextdata, crypttextdata):
    return int(max(numpy.subtract(cleartextdata, crypttextdata)))

def call_eq16(cleartextdata, crypttextdata):
    s = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        s+= x - y

    # return (s / (len(cleartextdata) * len(crypttextdata)))
    return s / len(cleartextdata)

def call_eq17(cleartextdata, crypttextdata):
    arrp = numpy.array(cleartextdata, dtype='int64')
    arrc = numpy.array(crypttextdata, dtype='int64')

    s1 = sum(numpy.power(arrp, 2))
    s2 = sum(numpy.power(arrc, 2))

    # TODO: equation is unusable because of input P always 0
    return float(s1 / s2)

def call_eq18(cleartextdata, crypttextdata):
    ap = sum(cleartextdata) / len(cleartextdata)
    ac = sum(crypttextdata) / len(crypttextdata)

    s1 = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        s1 += (x - ap) * (y - ac)

    s2 = 0
    for k in cleartextdata: 
        s2 += (k - ap) * (k - ap)

    s3 = 0
    for k in crypttextdata: 
        s3 += (k - ac) * (k - ac)    

    if s2 == 0 or s3 == 0:
        return 0
    
     # TODO: equation is unusable because of input P always 0
    return s1 / (math.sqrt(s2 * s3))

def call_eq19(cleartextdata, crypttextdata):
    s = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        if x == y:
            s += 0
        else:
            s += 1

    # return (s / (len(cleartextdata) * len(crypttextdata)))
    return s / len(cleartextdata)

def call_eq20(cleartextdata, crypttextdata):
    s = 0
    for x, y in zip(cleartextdata, crypttextdata): 
        s += abs(x - y) / 255

    # return (s / (len(cleartextdata) * len(crypttextdata)))
    return s / len(cleartextdata)

def call_eq21(cleartextdata, crypttextdata):
    freqs_xt = call_eq8_freq(crypttextdata)
    
    #e = len(cleartextdata) * len(crypttextdata) / 256
    e = len(cleartextdata) / 256

    s = 0
    for k in set(freqs_xt):
        s += ((freqs_xt.get(k, 0) - e)**2 / e)
        
    return s

def call_eq22(cleartextdata, crypttextdata):
    # TODO: equation 22 is virtually eq 18
    return call_eq18(cleartextdata, crypttextdata)

def call_eq23(cleartextdata, crypttextdata):
    freqs_xt = call_eq8_freq(crypttextdata)

    s = 0
    for k in set(freqs_xt):
        # TODO: the eqation does not check if probability is 0, also probability defined as frequency divided by total length of array
        if freqs_xt.get(k, 0) != 0:
            s += (freqs_xt.get(k, 0) / len(crypttextdata)) * math.log2(len(crypttextdata) / freqs_xt.get(k, 0))

    return s
    
def main():
    msg = "Implementing 15 equations, hopefully, from https://www.mdpi.com/2076-3417/14/7/2808"

    # Initialize parser
    parser = argparse.ArgumentParser(description = msg)

    parser.add_argument('cleartext', metavar='ct', 
                    help='cleartext file path')
    parser.add_argument('crypttext', metavar='xt',
                    help='cryptext file path')
    parser.add_argument('equations', metavar='eqs', nargs='+', type=argparse_equations_type,
                    help='insert equations here in the form of call_xxx')

    args = parser.parse_args()

    # now do all
    ctfile = Path(args.cleartext)
    if not ctfile.is_file():
        print("<" + args.cleartext + "> does not exists")
        exit()
    
    xtfile = Path(args.crypttext)
    if not xtfile.is_file():
        print("<" + args.crypttext + "> does not exists")
        exit()
    
    cleartextdata = []
    with open(args.cleartext, 'rb') as file:
        cleartextdata = bytearray(file.read())
    file.close

    crypttextdata = []
    with open(args.crypttext, 'rb') as file:
        crypttextdata = bytearray(file.read())
    file.close
    
    results = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    for eq in args.equations:
        if eq == 'call_eq8':
            reseq8 = call_eq8(cleartextdata, crypttextdata)
            results[8] = reseq8 
        if eq == 'call_eq9':
            reseq9 = call_eq9(cleartextdata, crypttextdata)
            results[9] = reseq9
        if eq == 'call_eq10':
            reseq10 = call_eq10(cleartextdata, crypttextdata)
            results[10] = reseq10
        if eq == 'call_eq11':
            reseq11 = call_eq11(cleartextdata, crypttextdata)
            results[11] = reseq11
        if eq == 'call_eq12':
            reseq12 = call_eq12(cleartextdata, crypttextdata)
            results[12] = reseq12
        if eq == 'call_eq13':
            reseq13 = call_eq13(cleartextdata, crypttextdata)
            results[13] = reseq13
        if eq == 'call_eq14':
            reseq14 = call_eq14(cleartextdata, crypttextdata)
            results[14] = reseq14
        if eq == 'call_eq15':
            reseq15 = call_eq15(cleartextdata, crypttextdata)
            results[15] = reseq15
        if eq == 'call_eq16':
            reseq16 = call_eq16(cleartextdata, crypttextdata)
            results[16] = reseq16
        if eq == 'call_eq17':
            reseq17 = call_eq17(cleartextdata, crypttextdata)
            results[17] = reseq17
        if eq == 'call_eq18':
            reseq18 = call_eq18(cleartextdata, crypttextdata)
            results[18] = reseq18
        if eq == 'call_eq19':
            reseq19 = call_eq19(cleartextdata, crypttextdata)
            results[19] = reseq19        
        if eq == 'call_eq20':
            reseq20 = call_eq20(cleartextdata, crypttextdata)
            results[20] = reseq20    
        if eq == 'call_eq21':
            reseq21 = call_eq21(cleartextdata, crypttextdata)
            results[21] = reseq21  
        if eq == 'call_eq22':
            reseq22 = call_eq22(cleartextdata, crypttextdata)
            results[22] = reseq22  
        if eq == 'call_eq23':
            reseq23 = call_eq23(cleartextdata, crypttextdata)
            results[23] = reseq23

    print(results)

if __name__ == "__main__":
    main()
