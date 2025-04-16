//
// Created by 17830 on 2024/4/21.
//
#include "multi-party-sig/multi-party-ecdsa/Li24/prg/prg.h"
#include "iostream"
void PRG::reset()
{
    hash_256.Reset();
}

void PRG::init(const safeheron::bignum::BN& data)
{
    num = data;
}

safeheron::bignum::BN PRG::rand()
{
/*    std::string str;
    num.ToHexStr(str);
    std::cout<<str<<std::endl;*/
    uint8_t inbuf[32];
    num.ToBytes32LE(inbuf);
    hash_256.Write(inbuf,32);
    uint8_t outbuf[32];
    hash_256.Finalize(outbuf);
    num = safeheron::bignum::BN::FromBytesLE(outbuf,32);
    return num;
}
