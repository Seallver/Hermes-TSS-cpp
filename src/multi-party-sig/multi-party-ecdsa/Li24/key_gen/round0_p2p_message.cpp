//
// Created by 17830 on 2024/4/23.
//
#include <google/protobuf/util/json_util.h>
#include "crypto-suites/crypto-encode/base64.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/key_gen/message.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using google::protobuf::util::Status;
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::JsonParseOptions;


namespace safeheron {
namespace multi_party_ecdsa{
namespace Li24{
namespace key_gen {
bool Round0P2PMessage::ToProtoObject(safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0P2PMessage &message) const {
    bool ok = true;

    std::string str;
    x_ij_.ToHexStr(str);
    message.set_x_ij(str);


    e_ij_.ToHexStr(str);
    message.set_e_ij(str);

    return true;
}

bool Round0P2PMessage::FromProtoObject(const safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0P2PMessage &message) {
    bool ok = true;

    x_ij_ = BN::FromHexStr(message.x_ij());
    if (x_ij_ == 0) return false;
    e_ij_ = BN::FromHexStr(message.e_ij());
    if (e_ij_ == 0) return false;

    return true;
}


typedef Round0P2PMessage TheClass;
typedef safeheron::proto::multi_party_ecdsa::Li24::key_gen::Round0P2PMessage ProtoObject;

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
}