#include <thread>
#include <future>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/exception/located_exception.h"
#include "multi-party-sig/multi-party-ecdsa/Li24/Li24.h"
#include "../../thread_safe_queue.h"
#include "../../message.h"
#include "../../party_message_queue.h"
#include "../../CTimer.h"
#include <mutex>

#include <fstream>
#include<math.h>
#include<map>

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::Li24::key_gen::Context;
using safeheron::multi_party_ecdsa::Li24::SignKey;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;

#define MIN_SIZE 5
#define MAX_SIZE 16
#define IS_NN 1
std::mutex mtx;
std::map<string,string>base64_arr_sepc;
string*base64_set[MAX_SIZE+1];
string*base64_set_p256[MAX_SIZE+1];

void print_context_stack_if_failed(Context *ctx) {
    std::string err_info;
    vector<ErrorInfo> error_stack;
    ctx->get_error_stack(error_stack);
    for(const auto &err: error_stack){
        err_info += "error code ( " + std::to_string(err.code_) + " ) : " + err.info_ + "\n";
    }
    printf("%s", err_info.c_str());
}


std::map<std::string, PartyMessageQue<Msg>> map_id_message_queue;


#define ROUNDS 2


bool key_gen(CurveType curve_type, std::string workspace_id, int threshold, int n_parties, std::string party_id, BN index, std::vector<std::string> remote_party_ids,std::vector<BN> remote_indexes ) {
    bool ok = true;
    std::string status;
    Context ctx(n_parties);
    ok = Context::CreateContext(ctx, curve_type, workspace_id, threshold, n_parties, party_id, index, remote_party_ids,remote_indexes);
    if (!ok) return false;

    for (int round = 0; round < ROUNDS; ++round) {
        if (round == 0) {
            ok = ctx.PushMessage();
            if (!ok) {
                print_context_stack_if_failed(&ctx);
                return false;
            }
        } else {
            for(int k = 0; k < n_parties - 1; k++) {
                Msg m;
                ThreadSafeQueue<Msg> &in_queue = map_id_message_queue.at(ctx.sign_key_.local_party_.party_id_).get(round - 1);
                in_queue.Pop(m);
                ok = ctx.PushMessage(m.p2p_msg_, m.bc_msg_, m.src_, round - 1);
                if (!ok) {
                    print_context_stack_if_failed(&ctx);
                    return false;
                }
            }
        }

        ok = ctx.IsCurRoundFinished();
        if (!ok) {
            print_context_stack_if_failed(&ctx);
            return false;
        }
        std::string out_bc_message;
        vector<string> out_p2p_message_arr;
        vector<string> out_des_arr;
        ok = ctx.PopMessages(out_p2p_message_arr, out_bc_message, out_des_arr);
        if (!ok) {
            print_context_stack_if_failed(&ctx);
            return false;
        }

        for (size_t j = 0; j < out_des_arr.size(); ++j) {
            Msg m = {ctx.sign_key_.local_party_.party_id_, out_bc_message, out_p2p_message_arr.empty() ? "": out_p2p_message_arr[j]};
            ThreadSafeQueue<Msg> &out_queue = map_id_message_queue.at(out_des_arr[j]).get(round);
            out_queue.Push(m);
        }
    }

    ok = ctx.IsFinished();
    if (!ok) {
        print_context_stack_if_failed(&ctx);
        return false;
    }

    string base64;
    ctx.sign_key_.ToBase64(base64);
    mtx.lock();
    base64_arr_sepc.insert(std::pair<string ,string>(party_id,base64));
    mtx.unlock();

    return true;
}

TEST(Li24, key_gen_mt) {
    std::future<bool> res[MAX_SIZE];
    for(int n=MIN_SIZE;n<=MAX_SIZE;n++) {
        base64_set[n] = new string [n];
        const int N_PARTIES = n;
        double N = n;
        double half_n = ceil(N/2);
        const int THRESHOLD = IS_NN?n:int(half_n);

        std::cout<<"n:"<<N_PARTIES<<" t:"<<THRESHOLD<<std::endl;

        std::string workspace_id = "workspace 0";

        std::string party_ids[N_PARTIES];
        BN indexes[N_PARTIES];
        for (int i = 1; i < N_PARTIES + 1; i++) {
            string str = "co_signer" + std::to_string(i);
            party_ids[i - 1] = str;
            indexes[i - 1] = BN(i);
        }

        for (int i = 0; i < N_PARTIES; ++i) {
            map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
        }
        for (int i = 0; i < N_PARTIES; ++i) {
            std::vector<std::string> remote_party_ids;
            std::vector<BN> remote_indexes;
            for (int j = 0; j < N_PARTIES; ++j) {
                if (j != i) {
                    remote_party_ids.push_back(party_ids[j]);
                    remote_indexes.push_back(indexes[j]);
                }
            }
            res[i] = std::async(std::launch::async, key_gen, CurveType::SECP256K1, workspace_id, THRESHOLD, N_PARTIES,
                                party_ids[i], indexes[i], remote_party_ids, remote_indexes);
        }
        for (int i = 0; i < N_PARTIES; ++i) {
            EXPECT_TRUE(res[i].get());
        }


        for(int i=0;i<n;i++)
        {
            string str = "co_signer"+std::to_string(i+1);
            base64_set[n][i] = base64_arr_sepc[str];
        }
        base64_arr_sepc.clear();
    }

    for(int n=MIN_SIZE;n<=MAX_SIZE;n++) {
        base64_set_p256[n] = new string [n];
        const int N_PARTIES = n;
        double N = n;
        double half_n = ceil(N/2);
        const int THRESHOLD = IS_NN?n:int(half_n);

        std::string workspace_id = "workspace 0";

        std::string party_ids[N_PARTIES];
        BN indexes[N_PARTIES];
        for (int i = 1; i < N_PARTIES + 1; i++) {
            string str = "co_signer" + std::to_string(i);
            party_ids[i - 1] = str;
            indexes[i - 1] = BN(i);
        }

        for (int i = 0; i < N_PARTIES; ++i) {
            map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
        }
        for (int i = 0; i < N_PARTIES; ++i) {
            std::vector<std::string> remote_party_ids;
            std::vector<BN> remote_indexes;
            for (int j = 0; j < N_PARTIES; ++j) {
                if (j != i) {
                    remote_party_ids.push_back(party_ids[j]);
                    remote_indexes.push_back(indexes[j]);
                }
            }
            res[i] = std::async(std::launch::async, key_gen, CurveType::P256, workspace_id, THRESHOLD, N_PARTIES,
                                party_ids[i], indexes[i], remote_party_ids, remote_indexes);
        }
        for (int i = 0; i < N_PARTIES; ++i) {
            EXPECT_TRUE(res[i].get());
        }
        for(int i =0;i<n;i++)
        {
            string str = "co_signer"+std::to_string(i+1);
            base64_set_p256[n][i] = base64_arr_sepc[str];
        }
        base64_arr_sepc.clear();
    }

    string file_name1 = IS_NN?"secp256k1_Li24_nn.txt":"secp256k1_Li24.txt";
    string file_name2 = IS_NN?"p256_Li24_nn.txt":"p256_Li24.txt";
    std::ofstream file1(file_name1);
    std::ofstream file2(file_name2);
    for(int i=MIN_SIZE;i<MAX_SIZE+1;i++)
        for(int j=0;j<i;j++)
        {
            std::cout<<base64_set[i][j]<<std::endl;
            std::cout<<base64_set_p256[i][j]<<std::endl;
            file1<<base64_set[i][j]<<std::endl;
            file2<<base64_set_p256[i][j]<<std::endl;
        }
    file1.close();
    file2.close();

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



