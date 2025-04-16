#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/context.h"

using std::string;

namespace safeheron {
namespace multi_party_ecdsa {
namespace Li24 {
namespace key_gen {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    // Sample u \in Z_q
    ctx->local_party_.u_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.y_ = curv->g * ctx->local_party_.u_;

    //prg seed
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        sign_key.local_party_.seed_.push_back(safeheron::rand::RandomBN(255));
    }

    // Sample coefficients in Z_n
    for(size_t i = 1; i < sign_key.threshold_; ++i){
        safeheron::bignum::BN num = safeheron::rand::RandomBNLt(curv->n);
        ctx->local_party_.rand_polynomial_coe_arr_.push_back(num);
    }

    std::vector<safeheron::bignum::BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    bool ok = true;
    ok = CheckIndexArr(share_index_arr, curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in CheckIndexArr!");
        return false;
    }

    safeheron::sss::vsss::MakeSharesWithCommitsAndCoes(ctx->local_party_.share_points_,
                                                       ctx->local_party_.vs_,
                                                       ctx->local_party_.u_,
                                                       (int)sign_key.threshold_,
                                                       share_index_arr,
                                                       ctx->local_party_.rand_polynomial_coe_arr_,
                                                       curv->n,
                                                       curv->g);

    // Last point belong to local party.
    sign_key.local_party_.x_ = ctx->local_party_.share_points_[share_index_arr.size() - 1].y;

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();


    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round0P2PMessage p2p_message;
        p2p_message.x_ij_ = ctx->local_party_.share_points_[i].y;
        p2p_message.e_ij_ = sign_key.local_party_.seed_[i];
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round0BCMessage bc_message;
    bc_message.vs_ = ctx->local_party_.vs_;
    bool ok = bc_message.ToBase64(out_bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message.ToBase64(out_bc_msg)!");
        return false;
    }

    return true;

}

}
}
}
}
