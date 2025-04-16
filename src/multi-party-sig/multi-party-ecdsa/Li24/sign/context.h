
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_CONTEXT_H

#include <vector>
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/t_party.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/round0.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/round1.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/round2.h"


namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

class Context : public safeheron::mpc_flow::mpc_parallel_v2::MPCContext {
public:
    /**
     * Default constructor
     */
    Context(int total_parties);

    /**
     * A copy constructor
     */
    Context(const Context &ctx);

    /**
     * A copy assignment operator
     */
    Context &operator=(const Context &ctx);

public:
    void BindAllRounds();

    static bool CreateContext(Context &ctx, const std::string &sign_key_base64, const safeheron::bignum::BN &m);

public:
    safeheron::multi_party_ecdsa::Li24::SignKey sign_key_;
    safeheron::bignum::BN m_;

    LocalTParty local_party_;

    std::vector<size_t> remote_party_indexes;
    size_t local_party_index;

    Round0 round0_;
    Round1 round1_;
    Round2 round2_;


    safeheron::bignum::BN delta_;
    safeheron::bignum::BN v_inv_;

    safeheron::curve::CurvePoint R_;
    safeheron::bignum::BN r_;
    safeheron::bignum::BN s_;
    uint32_t v_;

};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_Li24_SIGN_ONCE_CONTEXT_H
