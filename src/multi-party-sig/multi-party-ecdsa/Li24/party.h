
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_PARTY_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/proto_gen/struct.pb.switch.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/prg/prg.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{

class LocalParty {
public:
    std::string party_id_;
    // Share index
    safeheron::bignum::BN index_;

    // Original secret share
    safeheron::bignum::BN x_;
    // y = g^u
    safeheron::curve::CurvePoint g_x_;

    //prg
    std::vector<safeheron::bignum::BN> seed_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class RemoteParty {
public:
    std::string party_id_;
    // Share index
    safeheron::bignum::BN index_;

    //prg seed
    safeheron::bignum::BN seed_;

    // y = g^u
    safeheron::curve::CurvePoint g_x_;

    // prg
    PRG prg;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_PARTY_H
