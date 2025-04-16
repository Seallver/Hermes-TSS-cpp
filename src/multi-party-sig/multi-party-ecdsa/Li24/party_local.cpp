#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/party.h"

using std::string;
using safeheron::bignum::BN;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;

namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{


bool LocalParty::ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::Party &party) const {
    bool ok = true;
    string str;

    // reset
    party.clear_x();

    party.set_party_id(party_id_);

    index_.ToHexStr(str);
    party.set_index(str);


    x_.ToHexStr(str);
    party.set_x(str);

    safeheron::proto::CurvePoint point;
    ok = g_x_.ToProtoObject(point);
    if (!ok) return false;
    party.mutable_g_x()->CopyFrom(point);

    for(const auto & i : seed_){
        i.ToHexStr(str);
        party.add_seed(str);
    }

    return true;
}

bool LocalParty::FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::Party &party) {
    bool ok = true;

    party_id_ = party.party_id();
    ok = !party_id_.empty();
    if (!ok) return false;

    index_ = BN::FromHexStr(party.index());
    ok = (index_ != 0);
    if (!ok) return false;


    x_ = BN::FromHexStr(party.x());
    ok = (x_ != 0);
    if (!ok) return false;

    ok = g_x_.FromProtoObject(party.g_x());
    const curve::Curve *curv = curve::GetCurveParam(g_x_.GetCurveType());
    ok = ok && !g_x_.IsInfinity() && (g_x_ == curv->g * x_);
    if (!ok) return false;

    for(int i = 0; i < party.seed_size(); ++i){
        safeheron::curve::CurvePoint point;
        seed_.push_back(BN::FromHexStr(party.seed(i)));
    }


    return true;
}


typedef LocalParty TheClass;
typedef safeheron::proto::multi_party_ecdsa::Li24::Party ProtoObject;

bool TheClass::ToBase64(string &b64) const {
    bool ok = true;
    b64.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    string proto_bin = proto_object.SerializeAsString();
    b64 = safeheron::encode::base64::EncodeToBase64(proto_bin, true);
    return true;
}

bool TheClass::FromBase64(const string &b64) {
    bool ok = true;

    string data = safeheron::encode::base64::DecodeFromBase64(b64);

    ProtoObject proto_object;
    ok = proto_object.ParseFromString(data);
    if (!ok) return false;

    return FromProtoObject(proto_object);
}

bool TheClass::ToJsonString(string &json_str) const {
    bool ok = true;
    json_str.clear();
    ProtoObject proto_object;
    ok = ToProtoObject(proto_object);
    if (!ok) return false;

    JsonPrintOptions jp_option;
    jp_option.add_whitespace = true;
    Status stat = MessageToJsonString(proto_object, &json_str, jp_option);
    if (!stat.ok()) return false;

    return true;
}


bool TheClass::FromJsonString(const string &json_str) {
    ProtoObject proto_object;
    google::protobuf::util::JsonParseOptions jp_option;
    jp_option.ignore_unknown_fields = true;
    Status stat = JsonStringToMessage(json_str, &proto_object);
    if (!stat.ok()) return false;

    return FromProtoObject(proto_object);
}

}
}
}
