//
// Created by 17830 on 2024/4/21.
//

#ifndef MULTIPARTYSIG_PRG_H
#define MULTIPARTYSIG_PRG_H

#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-hash/sha256.h"

class PRG
{
private:
    safeheron::hash::CSHA256 hash_256;
    safeheron::bignum::BN num;

public:
    void reset();
    void init(const safeheron::bignum::BN& data);
    safeheron::bignum::BN rand();
};
#endif //MULTIPARTYSIG_PRG_H
