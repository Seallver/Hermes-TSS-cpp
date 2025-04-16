//
// Created by 何剑虹 on 2021/6/6.
//

#ifndef SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MPC_ROUND_H
#define SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MPC_ROUND_H

#include <string>
#include <vector>
#include <cassert>

#include "multi-party-sig/mpc-flow/mpc-parallel-v2/message_type.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/error_info.h"

namespace safeheron {
namespace mpc_flow {
namespace mpc_parallel_v2 {

class MPCContext;

class MPCRound {
    friend class MPCContext;

public:
    MPCRound(MessageType in_message_type, MessageType out_message_type): in_message_type_(in_message_type), out_message_type_(out_message_type){
        total_parties_ = 0;
        round_index_ = 0;
        msg_count_ = 0;
        is_finished_ = false;
        is_initiated_ = false;
        ctx_ = nullptr;
    }

    ~MPCRound() = default;;

public:
    virtual void Init() {};

    virtual bool
    ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) = 0;

    virtual bool ReceiveVerify(const std::string &party_id) = 0;

    virtual bool ComputeVerify() = 0;

    virtual bool MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const = 0;

private:
    void set_total_parties(int total) { total_parties_ = total; }

public:

    int get_total_parties() const { return total_parties_; }

    void set_round_index(int roundIndex) { round_index_ = roundIndex; }

    int get_round_index() const { return round_index_; }

    bool IsOver() const { return is_finished_; }

    void set_mpc_context(MPCContext *mpc_ptr) { ctx_ = mpc_ptr; }

    MPCContext *get_mpc_context() const { return ctx_; }

    std::string
    make_error_msg(int error_code_, const std::string &file_name, int line_num, const std::string &func_name,
                   const std::string &error_description);

    void set_initiated() { is_initiated_ = true; }

    int is_initiated() const { return is_initiated_; }

public:
    bool InternalPushMessage(int &error_code, std::string &error_msg);

    bool InternalPushMessage(const std::string &p2p_msg, const std::string &bc_msg, int round_index,
                             const std::string &party_id, int &error_code, std::string &error_msg);

    bool InternalPopMessages(std::vector<std::string> &out_p2p_msg_arr, std::string &out_broadcast_msg,
                             std::vector<std::string> &out_des_arr, int &error_code, std::string &error_msg);

private:
    MessageType in_message_type_;
    MessageType out_message_type_;
    // Context
    MPCContext *ctx_;
    // Total participators
    int total_parties_;
    // Round Index
    int round_index_;
    // Count the messages received
    int msg_count_;
    // Current round was finished
    bool is_finished_;

    // is initiated
    bool is_initiated_;

    std::vector<std::string> out_p2p_message_arr_;
    std::string out_broadcast_message_;
    std::vector<std::string> out_des_arr_;

    // Cache all messages received in the round
    // You should define inMessageCache for your own "Round"
    // std::vector<CustomObject> _inMessageCache;
};

}
}
}

#endif //SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MPC_ROUND_H
