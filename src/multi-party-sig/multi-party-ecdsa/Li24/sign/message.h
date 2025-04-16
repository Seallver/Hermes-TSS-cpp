
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_MESSAGE_H

#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/proto_gen/sign.pb.switch.h"
#include "crypto-suites/crypto-curve/curve.h"
namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

class Round0BCMessage {
public:
    safeheron::curve::CurvePoint Gk_;


public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::sign::Round0BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::sign::Round0BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round0P2PMessage {
public:
    safeheron::bignum::BN k_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN phi_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::sign::Round0P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::sign::Round0P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    safeheron::bignum::BN delta_;
    safeheron::bignum::BN v_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::sign::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::sign::Round1P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};


}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_MESSAGE_H
