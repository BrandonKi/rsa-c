/**
 * @file rsa.h
 * @author Brandon Kirincich
 * @brief an rsa implementation that is not secure for important data
 * this was made be fast and to avoid storing data as plaintext but doesn't ensure complete safety
 * @version 0.1
 * @date 2021-03-01
 * 
 * @copyright MIT License
 *
 * Copyright (c) 2021 Brandon Kirincich
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * 
 */

#include <inttypes.h>
#include <time.h>
#include <math.h>

typedef int16_t i16;
typedef int64_t i64;
typedef uint64_t u64;

typedef struct rsa_buffer {
    size_t size;
    char *data;
} rsa_buffer;

typedef struct private_key {
    u64 n;
    u64 d;
} private_key;

typedef struct public_key {
    u64 n;
    u64 e;
} public_key;

u64 n;
u64 e;
u64 d;

/**
 * get the private key
 * 
 * @return private_key 
 */
private_key get_private_key() {
    return (private_key){n, d};
}

/**
 * get the public key
 * 
 * @return public_key 
 */
public_key get_public_key() {
    return (public_key){n, e};
}

/**
 * set the private key to the provided value
 * 
 * @param key 
 */
void use_private_key(private_key key) {
    n = key.n;
    d = key.d;
}

/**
 * set the public key to the provided value
 * 
 * @param key 
 */
void use_public_key(public_key key) {
    n = key.n;
    e = key.e;
}

/**
 * find the greatest common divisor of two numbers
 * 
 * 
 * @param a 
 * @param b 
 * @return u64 the gcd
 */
u64 gcd(u64 a, u64 b) {
    u64 t;
    while (b != 0) {
        t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/**
 * uses the Extended Euclidean algorithm
 * to calulate the modular multiplicative inverse of a % n
 *  
 * @param a 
 * @param n 
 * @return u64 the result
 */
u64 mmi(i64 a, i64 n) {

    i64 t = 0;
    i64 new_t = 1;
    i64 r = n;
    i64 new_r = a;

    i64 old_r;
    i64 old_t;

    i64 quotient;
    while (new_r != 0) {
        quotient = r / new_r;

        old_r = r;
        r = new_r;
        new_r = old_r - quotient * new_r;
        
        old_t = t;
        t = new_t;
        new_t = old_t - quotient * new_t;
    }

    if (t < 0)
        t = t + n;

    return t;
}

/**
 * finc the least common multiple
 * between two numbers
 * this is computed by using the greatest common divisor
 * 
 * @param a 
 * @param b 
 * @return u64 
 */
u64 lcm(u64 a, u64 b) {
    return (a / gcd(a,b)) * b;
}

/**
 * convenience function to get a random number
 * in a specified range
 * 
 * @param lower lower bound
 * @param upper upper bound
 * @return i64 random number
 */
i64 rand_num_in_range(i64 lower, i64 upper) {
    return rand() % (upper + 1 - lower) + lower;
}

/**
 * get a random number coprime to the paramter a
 * 
 * @param a
 * @return i64 a number coprime to a
 */
i64 get_coprime(i64 a) {
    for (i64 b;;) {
        b = rand_num_in_range(2, a);

        if (gcd(b, a) == 1)
            return b;
    }
}

/**
 * get a random prime number that is small enough to not overflow
 * 
 * @return i64 a random prime number
 */
i64 get_random_prime() {
    i16 primes[] = { 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987 };
    return primes[rand_num_in_range(0, sizeof(primes) / sizeof(primes[0]))];
}

/**
 * generates a set of public and private keys
 * 
 */
void generate_keys() {

    // let p, q = prime numbers
    // totient = lcm(p - 1, q - 1)
    // let e = a number coprime to totient and 0 < e < totient

    srand(time(0));

    i64 p = get_random_prime();
    i64 q = get_random_prime();

    n = p * q;

    i64 totient = lcm(p - 1, q - 1);

    e = get_coprime(totient); // totient

    d = mmi(e, totient);

    printf("public key:\n\t%zu %zu\n", n, d);
    printf("private key:\n\t%zu %zu\n", n, e);
    fflush(stdout);
}

/**
 * uses the Right-to-left binary method
 * does not check for overflow because it shouldn't be possible
 * it will only overflow if pow(n - 1, 2) does not overflow b
 * this function does the equivalent of pow(b, e) % n
 * 
 * @param b the base number
 * @param e the exponent
 * @param n the number to mod by
 * @return i64 pow(b, e) % n
 */
i64 modular_pow(i64 b, i64 e, i64 n) {
    if (n == 1)
        return 0;
    i64 result = 1;
    b = b % n;
    while (e > 0) {
        if (e % 2 == 1)
            result = (result * b) % n;
        e = e >> 1;
        b = (b * b) % n;
    }
    return result;
}

/**
 * encrpyts the text by doing 
 * c^e % n
 * encrypts each character individually at the moment
 * 
 * @param input a rsa_buffer containing the data to encrypt
 * @return rsa_buffer a rsa_buffer with the encryped data
 */
rsa_buffer encrypt(rsa_buffer input) {
    rsa_buffer output;
    output.data = calloc(input.size, sizeof(i64));
    output.size = input.size;

    i64 *temp_data = (i64*)output.data;

    for(u64 i = 0; i < input.size; i++) {
        temp_data[i] = modular_pow(input.data[i], e, n);
        printf(/*"%c"*/"%" PRId64 " "/*"\n", input.data[i]*/, temp_data[i]);
    }

    return output;      //TODO return the correct value
}

/**
 * decrypts the text using this algorithm 
 * pow(c, d) % n
 * at the moment each character is encrypted/decrypted individually
 * 
 * @param input a rsa_buffer containing the encrypted data
 * @return rsa_buffer the decrypted data
 */
rsa_buffer decrypt(rsa_buffer input) {
    
    const char s[2] = " ";
    char *token;
    
    // it is theoroetically impossible to overflow this buffer
    // there is prorbably a better/safer way to do this though
    rsa_buffer output = {input.size, calloc(input.size / 2, 1)};


    /* get the first token */
    token = strtok(input.data, s);
    
    /* walk through other tokens */
    for(u64 i = 0; token != NULL; i++) {
        i64 temp = modular_pow(strtoimax(token, NULL, 10), d, n);
        // printf("%" PRId64 "\n", temp);
        output.data[i] = (char)temp;
        printf("%c", output.data[i]);
        token = strtok(NULL, s);
    }

    // FIXME everything under this comment needs to be fixed
    // output.size = strlen(output.data);
    for(output.size = input.size/2 - 1; output.size >= 0 && output.data[output.size] == '\0'; output.size--) { }
    ++output.size;
    // printf("%zu\n", output.size);   //TODO off by one and needs a null byte
    return output;  //TODO return the correct value

}
