#include <utility>
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/context.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::Li24::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

Context::Context(int total_parties): MPCContext(total_parties){
    BindAllRounds();
}

Context::Context(const Context &ctx): MPCContext(ctx){
    // Assign all the member variables.
    sign_key_ = ctx.sign_key_;

    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;

    remote_party_indexes = ctx.remote_party_indexes;
    local_party_index = ctx.local_party_index;

    delta_ = ctx.delta_;
    v_inv_ = ctx.v_inv_;

    R_ = ctx.R_;
    r_ = ctx.r_;
    s_ = ctx.s_;
    v_ = ctx.v_;
    // End Assignments.

    BindAllRounds();
}

Context &Context::operator=(const Context &ctx){
    if (this == &ctx) {
        return *this;
    }

    MPCContext::operator=(ctx);

    // Assign all the member variables.
    sign_key_ = ctx.sign_key_;

    m_ = ctx.m_;

    local_party_ = ctx.local_party_;
    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;

    remote_party_indexes = ctx.remote_party_indexes;
    local_party_index = ctx.local_party_index;

    delta_ = ctx.delta_;
    v_inv_ = ctx.v_inv_;

    R_ = ctx.R_;
    r_ = ctx.r_;
    s_ = ctx.s_;
    v_ = ctx.v_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx, const std::string &sign_key_base64, const safeheron::bignum::BN &m) {
    bool ok = true;
    ctx.m_ = m;

    ok = ctx.sign_key_.FromBase64(sign_key_base64);
    if (!ok) return false;
    ok = ((int)ctx.sign_key_.n_parties_ == ctx.get_total_parties());
    if (!ok) return false;

    return true;
}

void Context::BindAllRounds() {
    RemoveAllRounds();
    AddRound(&round0_);
    AddRound(&round1_);
    AddRound(&round2_);
}

}
}
}
}
