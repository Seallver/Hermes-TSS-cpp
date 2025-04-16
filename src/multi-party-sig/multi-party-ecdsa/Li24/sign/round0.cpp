
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/round0.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/sign/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::Li24::SignKey;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace sign{
bool Round0::MakeP2PMessage(size_t start,size_t end,std::vector<std::string> &out_p2p_msg_arr)const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    if (end < start)
    {
        for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
            Round0P2PMessage p2p_message;
            if(ctx->remote_party_indexes[i]<=end ||ctx->remote_party_indexes[i]>=start)
            {
                p2p_message.k_ = ctx->local_party_.k_;
                p2p_message.w_ = ctx->local_party_.w_;
                p2p_message.phi_ = ctx->local_party_.phi_;
            }
            else
            {
                p2p_message.k_ = BN(0);
                p2p_message.w_ = BN(0);
                p2p_message.phi_ = BN(0);
            }
            string base64;
            bool ok = p2p_message.ToBase64(base64);
            if (!ok) {
                ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
                return false;
            }
            out_p2p_msg_arr.push_back(base64);
        }
    }
    if (start <= end)
    {
        for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
            Round0P2PMessage p2p_message;
            if (ctx->remote_party_indexes[i]<=end && ctx->remote_party_indexes[i]>=start)
            {
                p2p_message.k_ = ctx->local_party_.k_;
                p2p_message.w_ = ctx->local_party_.w_;
                p2p_message.phi_ = ctx->local_party_.phi_;
            }
            else
            {
                p2p_message.k_ = BN(0);
                p2p_message.w_ = BN(0);
                p2p_message.phi_ = BN(0);
            }
            string base64;
            bool ok = p2p_message.ToBase64(base64);
            if (!ok) {
                ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
                return false;
            }
            out_p2p_msg_arr.push_back(base64);
        }
    }
    return true;
}
bool Round0::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // Compute w = x * lambda mod q
    vector<BN> share_index_arr;
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
        ctx->remote_party_indexes.emplace_back();
    }
    share_index_arr.push_back(sign_key.local_party_.index_);
    vector<BN> &l_arr = ctx->local_party_.l_arr_;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);
    ctx->local_party_.lambda_ = l_arr[share_index_arr.size()-1];
    ctx->local_party_.w_ = (sign_key.local_party_.x_ * ctx->local_party_.lambda_) % curv->n;


    std::sort(share_index_arr.begin(), share_index_arr.end());
    for (size_t i = 0; i < share_index_arr.size(); ++i) {
        if(sign_key.local_party_.index_ == share_index_arr[i])
        {
            ctx->local_party_index = i;
            break;
        }
    }
    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        for (size_t j = 0; j < share_index_arr.size(); ++j) {
            if(sign_key.remote_parties_[i].index_ == share_index_arr[j])
            {
                ctx->remote_party_indexes[i] = j;
                break;
            }
        }
    }


    // Sample k_i, phi_i in Z_q
    ctx->local_party_.k_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.phi_ = safeheron::rand::RandomBNLt(curv->n);

    //computes the blinding shares in sequence using PRG
    BN temp(0);
    for (size_t i = 0; i < ctx->remote_party_indexes.size(); ++i) {
        if(ctx->local_party_index > ctx->remote_party_indexes[i])
        {
            temp += ctx->sign_key_.remote_parties_[i].prg.rand();
        }
        else
        {
            temp -= ctx->sign_key_.remote_parties_[i].prg.rand();
        }
    }
    ctx->local_party_.k_ = (ctx->local_party_.k_ + temp) % curv->n;
    temp = BN(0);
    for (size_t i = 0; i < ctx->remote_party_indexes.size(); ++i) {
        if(ctx->local_party_index > ctx->remote_party_indexes[i])
        {
            temp += ctx->sign_key_.remote_parties_[i].prg.rand();
        }
        else
        {
            temp -= ctx->sign_key_.remote_parties_[i].prg.rand();
        }
    }
    ctx->local_party_.phi_ = (ctx->local_party_.phi_ + temp) % curv->n;
    temp = BN(0);
    for (size_t i = 0; i < ctx->remote_party_indexes.size(); ++i) {
        if(ctx->local_party_index > ctx->remote_party_indexes[i])
        {
            temp += ctx->sign_key_.remote_parties_[i].prg.rand();
        }
        else
        {
            temp -= ctx->sign_key_.remote_parties_[i].prg.rand();
        }
    }
    ctx->local_party_.w_ = (ctx->local_party_.w_ + temp) % curv->n;

    //GK_
    ctx->local_party_.Gk_ = curv->g * ctx->local_party_.k_;

/*    std::string str;
    ctx->local_party_.w_.ToHexStr(str);
    std::cout<<str<<std::endl;
    BN num1 = BN::FromHexStr("63CA9FE7582C6BFAD8683CB229B85948E01BD1EFE11D3A7FC7BE59C739E05A2E");
    BN num2 = BN::FromHexStr("495CBC89EACC4B1461282BA373C6DE0F8B78D854ED63ADCFBEF9A4CA8DACD6AF");
    BN num3 = BN::FromHexStr("A478DD293081EF94834C7A0D31D0C752F78A9E9008DA73D559C4E6ED276D1FDE");

    CurvePoint point =  curv->g * ((num1+num2+num3)%curv->n);
    point.x().ToHexStr(str);
    std::cout<<str<<std::endl;*/

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }
    bool ok = true;

    // make message p2p
    size_t start = (ctx->local_party_index + 1) % sign_key.threshold_;
    if(sign_key.threshold_ % 2 == 1) // t+1是奇数,即t是偶数
    {
        size_t end = (ctx->local_party_index + (sign_key.remote_parties_.size()/2)) % sign_key.threshold_;
        ok = MakeP2PMessage(start,end,out_p2p_msg_arr);
        if(!ok) return false;
    }
    else //t是偶数
    {
        if(ctx->local_party_index<sign_key.threshold_/2)
        {
            size_t end = (ctx->local_party_index + (sign_key.threshold_/2)) % sign_key.threshold_;
            ok = MakeP2PMessage(start,end,out_p2p_msg_arr);
            if(!ok) return false;
        }
        else
        {
            size_t end = (ctx->local_party_index + (sign_key.threshold_/2) -1) % sign_key.threshold_;
            ok = MakeP2PMessage(start,end,out_p2p_msg_arr);
            if(!ok) return false;
        }
    }

    Round0BCMessage bc_message;
    bc_message.Gk_ = ctx->local_party_.Gk_;
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
