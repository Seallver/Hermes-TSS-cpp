#include <cstdio>
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/round1.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace key_gen {

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize bc_message from base64!");
        return false;
    }

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64(p2p)!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    bool ok = true;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    if (!safeheron::sss::vsss::VerifyShare(bc_message_arr_[pos].vs_, sign_key.threshold_, sign_key.local_party_.index_, p2p_message_arr_[pos].x_ij_, curv->g, curv->n)) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify VsssSecp256k1::VerifyShare!");
        return false;
    }


    return true;
}

bool Round1::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        sign_key.remote_parties_[i].seed_ = p2p_message_arr_[i].e_ij_ + sign_key.local_party_.seed_[i];
        ctx->remote_parties_[i].y_= bc_message_arr_[i].vs_[0];
    }

    CurvePoint pub = ctx->local_party_.y_;

    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        pub += bc_message_arr_[i].vs_[0];
    }

    ok = !pub.IsInfinity();
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid public key!");
        return false;
    }

    ctx->X_ = pub;

    sign_key.X_ = pub;

    // Compute the new share
    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        sign_key.local_party_.x_ = (sign_key.local_party_.x_ + p2p_message_arr_[i].x_ij_) % curv->n;
    }
    sign_key.local_party_.g_x_ = curv->g * sign_key.local_party_.x_;

    //初始化种子
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        sign_key.remote_parties_[i].prg.init(sign_key.remote_parties_[i].seed_);
    }

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    return true;
}

}
}
}
}
