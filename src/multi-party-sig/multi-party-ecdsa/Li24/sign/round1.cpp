#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/round1.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::Li24::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
        bc_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    return true;
}

bool Round1::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    safeheron::curve::CurvePoint GK;
    GK = ctx->local_party_.Gk_;
    for (size_t i = 0; i < bc_message_arr_.size(); ++i) {
        GK += bc_message_arr_[i].Gk_;
    }
    ctx->r_ = GK.x();
    ctx->R_ = GK;

    BN wi = ctx->local_party_.w_;
    BN ki = ctx->local_party_.k_;
    BN phii = ctx->local_party_.phi_;
    BN ui = wi * phii;
    BN vi = ki * phii;
    for (size_t i = 0; i < p2p_message_arr_.size(); ++i) {
        ui += (wi *  p2p_message_arr_[i].phi_ +  phii * p2p_message_arr_[i].w_) % curv->n;
        vi += (ki *  p2p_message_arr_[i].phi_ +  phii * p2p_message_arr_[i].k_) % curv->n;
    }
    ctx->local_party_.u_ = ui;
    ctx->local_party_.v_ = vi;
    ctx->local_party_.delta_ = (ctx->m_ * phii + ctx->r_ * ui) %curv->n;
    ctx->delta_ = ctx->local_party_.delta_;

/*    std::string str;
    ctx->r_.ToHexStr(str);
    std::cout<<str<<std::endl;*/
    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    bool ok = true;
    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round1BCMessage bc_message;
    bc_message.v_ = ctx->local_party_.v_;
    bc_message.delta_ = ctx->delta_;
    ok = bc_message.ToBase64(out_bc_msg);
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
