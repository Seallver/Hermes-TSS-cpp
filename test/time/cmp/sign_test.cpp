
#include <cstring>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "crypto-suites/exception/located_exception.h"
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/cmp.h"
#include "../../message.h"
#include <fstream>
#include<math.h>

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::cmp::sign::Context;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;
using safeheron::multi_party_ecdsa::cmp::sign::ProofInPreSignPhase;
using safeheron::multi_party_ecdsa::cmp::sign::ProofInSignPhase;


#define MIN_SIZE 5
#define MAX_SIZE 16
#define ROUNDS 5
#define TURNS 1
#define IS_NN 1
double vector_aver(vector<double> v)
{
    size_t size = v.size();
    double total_time_ = 0;
    for(size_t i = 0;i < size;i++)
        total_time_+=v[i];
    double aver_time = total_time_/double(size);
    return aver_time;
}


void print_context_stack_if_failed(Context *ctx_ptr, bool failed){
    if(failed){
        vector<ErrorInfo> error_stack;
        ctx_ptr->get_error_stack(error_stack);
        for(const auto &err: error_stack){
            std::cout << "error code (" << err.code_ << "): " << err.info_ << std::endl;
        }
    }
}


void run_round(Context *ctx_ptr, const std::string& party_id, int round_index,
               std::map<std::string, std::vector<Msg>> &map_id_queue) {
    bool ok = true;

    std::vector<string> out_p2p_message_arr;
    string out_bc_message;
    std::vector<string> out_des_arr;

    if (round_index == 0) {
        ok = ctx_ptr->PushMessage();
        print_context_stack_if_failed(ctx_ptr, !ok);
        ok = ctx_ptr->PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
        print_context_stack_if_failed(ctx_ptr, !ok);
        for (size_t k = 0; k < out_des_arr.size(); ++k) {
            map_id_queue[out_des_arr[k]].push_back({
                                                           party_id,
                                                           out_bc_message,
                                                           out_p2p_message_arr.empty() ? string()
                                                                                       : out_p2p_message_arr[k]
                                                   });
        }
    } else {
        std::vector<Msg>::iterator iter;
        for (iter = map_id_queue[party_id].begin(); iter != map_id_queue[party_id].end(); ) {
            ok = ctx_ptr->PushMessage(iter->p2p_msg_, iter->bc_msg_, iter->src_, round_index - 1);
            print_context_stack_if_failed(ctx_ptr, !ok);
            iter = map_id_queue[party_id].erase(iter);

            if (ctx_ptr->IsCurRoundFinished()) {
                ok = ctx_ptr->PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
                print_context_stack_if_failed(ctx_ptr, !ok);
                for (size_t k = 0; k < out_des_arr.size(); ++k) {
                    map_id_queue[out_des_arr[k]].push_back({
                                                                   party_id,
                                                                   out_bc_message,
                                                                   out_p2p_message_arr.empty() ? string()
                                                                                               : out_p2p_message_arr[k]
                                                           });
                }
                break;
            }
        }
    }
}


vector<double> Round_time_per_t;

void testCoSign_t_n(std::vector<std::string> &sign_key_base64,int threshold,int n_parties) {
    bool ok = true;
    int t = threshold;
    int n = n_parties;
    std::map<std::string, std::vector<Msg>> map_id_message_queue;

    safeheron::bignum::BN m = BN("1234567812345678123456781234567812345678123456781234567812345678", 16);

    std::vector<string> participant_id_arr;
    for(size_t i = 0;i<t;i++)
    {
        string str = "co_signer" + std::to_string(i+1);
        participant_id_arr.push_back(str);
    }
    for(size_t i = 0;i<t;i++)
    {
        ok = safeheron::multi_party_ecdsa::cmp::trim_sign_key(sign_key_base64[i], sign_key_base64[i], participant_id_arr);
        if(!ok) std::cout << "Failed to prepare sign key" << std::endl;
    }
    vector<Context>party_context;
    for(size_t i = 0;i<t;i++)
    {
        Context party_context_temp(t);
        party_context.push_back(party_context_temp);
    }
    string ssid("ssid");
    for(size_t i = 0;i<t;i++)
    {
        ok = Context::CreateContext(party_context[i], sign_key_base64[i], m,ssid);
        EXPECT_TRUE(ok);
    }
    vector<Context *> ctx_arr;
    for(size_t i = 0;i<t;i++)
    {
        ctx_arr.push_back(&party_context[i]);
    }

    try {
        vector<double> time_total_party_per_round;
        for (int round = 0; round <ROUNDS; ++round) {
            for (int i = 0; i < t; ++i) {
                std::chrono::high_resolution_clock::time_point begin_round = std::chrono::high_resolution_clock::now();
                run_round(ctx_arr[i], ctx_arr[i]->sign_key_.local_party_.party_id_, round, map_id_message_queue);
                std::chrono::high_resolution_clock::time_point end_round = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> duration = end_round - begin_round;
                time_total_party_per_round.push_back(duration.count());
            }
            Round_time_per_t.push_back(vector_aver(time_total_party_per_round));
            time_total_party_per_round.clear();
        }
    } catch (const safeheron::exception::LocatedException &e) {
        std::cout << e.what() << std::endl;
    }
}

string*base64_set[MAX_SIZE+1];
string*base64_set_p256[MAX_SIZE+1];

TEST(CoSign, Sign_t_n)
{
    string file_name_1 = IS_NN?"secp256k1_cmp_nn.txt":"secp256k1_cmp.txt";
    string file_name_2 = IS_NN?"p256_cmp_nn.txt":"p256_cmp.txt";
    std::ifstream file1(file_name_1);
    std::ifstream file2(file_name_2);
    string line;
    for (int i = MIN_SIZE; i < MAX_SIZE + 1; i++) {
        base64_set_p256[i] = new string[i];
        base64_set[i] = new string[i];
        for (int j = 0; j < i; j++) {
            getline(file1, line);
            base64_set[i][j] = line;
            getline(file2, line);
            base64_set_p256[i][j] = line;
        }
    }
    file1.close();
    file2.close();
    std::cout<<"cmp:"<<std::endl;
    for (int i = MIN_SIZE; i < MAX_SIZE+1; ++i) {
        double N = i;
        double half_n = ceil(N / 2);
        const int threshold = IS_NN ? i : int(half_n);
        std::cout << "n = " << i << std::endl;
        std::cout << "SECP256K1:" << std::endl;

        vector<string> sign_key_base64;
        for (int j = 0; j < i; j++) {
            sign_key_base64.push_back(base64_set[i][j]);
        }
        vector<double> turn_time;
        for (size_t t = 0; t < TURNS; t++) {
            testCoSign_t_n(sign_key_base64, threshold, i);
            double time = 0;
            for (size_t r = 0; r < ROUNDS; r++) {
                time += Round_time_per_t[r];
            }
            Round_time_per_t.clear();
            turn_time.push_back(time);
        }
        double Time = 0;
        for (size_t t = 0; t < turn_time.size(); t++) {
            Time += turn_time[t];
        }
        turn_time.clear();
        std::cout << "sign time：" << Time / TURNS << "\n";
        std::cout << "P256:" << std::endl;

        for (int j = 0; j < i; j++) {
            sign_key_base64[j] = base64_set_p256[i][j];
        }
        for (size_t t = 0; t < TURNS; t++) {
            testCoSign_t_n(sign_key_base64, threshold, i);
            double time = 0;
            for (size_t r = 0; r < ROUNDS; r++) {
                time += Round_time_per_t[r];
            }
            Round_time_per_t.clear();
            turn_time.push_back(time);
        }
        Time = 0;
        for (size_t t = 0; t < turn_time.size(); t++) {
            Time += turn_time[t];
        }
        std::cout << "sign time：" << Time / TURNS << "\n";
        turn_time.clear();
    }
    for(int i =0;i<MAX_SIZE+1;i++) {
        delete[]base64_set[i];
        delete[]base64_set_p256[i];
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
