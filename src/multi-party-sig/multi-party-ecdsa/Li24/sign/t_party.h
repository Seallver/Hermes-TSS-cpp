

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_T_PARTY_H


#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

class LocalTParty {
public:
    // Phase 1
    safeheron::bignum::BN lambda_;
    std::vector<safeheron::bignum::BN> l_arr_;
    // - Sample gamma, k
    safeheron::bignum::BN phi_;
    safeheron::bignum::BN k_;
    safeheron::bignum::BN w_;
    // - Gk
    safeheron::curve::CurvePoint Gk_;

    //Phase2
    safeheron::bignum::BN u_;
    safeheron::bignum::BN v_;
    safeheron::bignum::BN delta_;

};


}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_T_PARTY_H
