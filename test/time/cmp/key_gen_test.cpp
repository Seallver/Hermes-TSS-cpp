#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include <string>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/exception/located_exception.h"
#include "../../CTimer.h"
#include "../../message.h"

#include <fstream>
#include<math.h>
#include<map>

#define MIN_SIZE 5
#define MAX_SIZE 16
#define IS_NN 1

std::string*base64_set[MAX_SIZE+1];
std::string*base64_set_p256[MAX_SIZE+1];

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::cmp::key_gen::Context;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;

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

void testKeyGen_t_n(CurveType curve_type) {
    string workspace_id("workspace_0");

    std::map<std::string, std::vector<Msg>> map_id_message_queue;

    for(int n = MIN_SIZE;n<=MAX_SIZE;n++)
    {
        const int n_parties = n;
        double N = n;
        double half_n = ceil(N/2);
        const int threshold = IS_NN?n:int(half_n);
        std::cout<<"n:"<<n_parties<<" t:"<<threshold<<std::endl;
        std::vector<string> party_id_arr;
        BN party_index[n_parties];
        vector<Context> party_context;
        for (int i = 1; i < n_parties + 1; i++) {
            string str = "co_signer" + std::to_string(i);
            party_id_arr.push_back(str);
            party_index[i-1] = BN(i);
            party_context.push_back(Context(n_parties));
        }
        string sid = "sid";
        vector<string> remote_party_id_arr;
        vector<BN> remote_party_index_arr;
        int p;
        for(p = 1;p<n_parties;p++)
        {
            for(int i =1;i<=n_parties;i++)
            {
                if(i==p)continue;
                remote_party_id_arr.push_back(party_id_arr[i-1]);
                remote_party_index_arr.push_back(party_index[i-1]);
            }
            Context::CreateContext(
                    party_context[p-1],
                    curve_type,
                    threshold, n_parties,
                    party_index[p-1],
                    party_id_arr[p-1],
                    remote_party_index_arr,
                    remote_party_id_arr,
                    sid
            );
            remote_party_index_arr.clear();
            remote_party_id_arr.clear();
        }
        for(int i =1;i<=n_parties;i++)
        {
            if(i==p)continue;
            remote_party_id_arr.push_back(party_id_arr[i-1]);
            remote_party_index_arr.push_back(party_index[i-1]);
        }
        BN N_, s, t, p_, q, alpha, beta;
        safeheron::multi_party_ecdsa::cmp::prepare_data(N_, s, t, p_, q, alpha, beta);
        Context::CreateContext(party_context[p-1],
                               curve_type,
                               threshold, n_parties,
                               party_index[p-1],
                               party_id_arr[p-1],
                               remote_party_index_arr,
                               remote_party_id_arr,
                               sid,N_,s,t,p_,q,alpha,
                               beta
        );
        vector<Context *> ctx_arr;
        for(int i=0;i<n_parties;i++)
        {
            ctx_arr.push_back(&party_context[i]);
        }
        for (int round = 0; round <= 6; ++round) {
            for (int i = 0; i < n_parties; ++i) {
                run_round(ctx_arr[i], party_id_arr[i], round, map_id_message_queue);
            }
        }

        switch (curve_type) {
            case safeheron::curve::CurveType::P256: {
                base64_set_p256[n] = new string [n];
                for (int i = 0; i < n_parties; ++i) {
                    string base64;
                    EXPECT_TRUE(ctx_arr[i]->sign_key_.ToBase64(base64));
                    base64_set_p256[n][i] = base64;
                }
                break;
            }
            case safeheron::curve::CurveType::SECP256K1:{
                base64_set[n] = new string [n];
                for (int i = 0; i < n_parties; ++i) {
                    string base64;
                    EXPECT_TRUE(ctx_arr[i]->sign_key_.ToBase64(base64));
                    base64_set[n][i] = base64;
                }
                break;
            }
            default:
                std::cout<<"error"<<std::endl;
        }
    }

    };


TEST(KeyGen, KeyGen_t_n)
{
    try {
        std::cout << "Test cmp key generation with SECP256K1 curve:" << std::endl;
        testKeyGen_t_n(safeheron::curve::CurveType::SECP256K1);

        std::cout << "Test cmp key generation with P256 curve:" << std::endl;
        testKeyGen_t_n(safeheron::curve::CurveType::P256);
        string file_name1 = IS_NN?"secp256k1_cmp_nn.txt":"secp256k1_cmp.txt";
        string file_name2 = IS_NN?"p256_cmp_nn.txt":"p256_cmp.txt";
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

    } catch (const safeheron::exception::LocatedException &e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
