
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/proto_gen/key_gen.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace key_gen {


class Round0BCMessage {
public:
    std::vector<safeheron::curve::CurvePoint> vs_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0BCMessage &message)const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0BCMessage &message);

    bool ToBase64(std::string &b64)const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round0P2PMessage {
public:
    safeheron::bignum::BN x_ij_;
    safeheron::bignum::BN e_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};



}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_KEY_GEN_MESSAGE_H
