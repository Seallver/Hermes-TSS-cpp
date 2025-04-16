#include <thread>
#include <future>
#include <vector>
#include <google/protobuf/stubs/common.h>
#include "crypto-suites/exception/located_exception.h"
#include "gtest/gtest.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/gg20.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/util.h"
#include "../../thread_safe_queue.h"
#include "../../message.h"
#include "../../party_message_queue.h"
#include <fstream>
#include<math.h>

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::multi_party_ecdsa::gg20::sign::Context;
using safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo;

#define MIN_SIZE 5
#define MAX_SIZE 16
#define TURNS 1
#define SLEEP_TIME 1500
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
double sum_vector(double v[],size_t len)
{
    double sum = 0;
    for(size_t i = 0;i < len;i++)
        sum+=v[i];
    return sum;
}




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

#define ROUNDS 8


vector<double> Round_time[ROUNDS];

bool sign(std::string sign_key_base64, std::vector<std::string> participants, BN m,int t_id) {
    std::string t_sign_key_base64;
    bool ok = safeheron::multi_party_ecdsa::gg18::trim_sign_key(t_sign_key_base64, sign_key_base64, participants);
    if (!ok) return false;

    Context ctx(participants.size());

    ok = Context::CreateContext(ctx, t_sign_key_base64, m);
    if (!ok) return false;

    for (int round = 0; round < ROUNDS; ++round) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
        std::chrono::high_resolution_clock::time_point begin_round = std::chrono::high_resolution_clock::now();
        if (round == 0) {
            ok = ctx.PushMessage();
            if (!ok) {
                print_context_stack_if_failed(&ctx);
                return false;
            }
        } else {
            for(size_t k = 0; k < participants.size() - 1; k++) {
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
        std::chrono::high_resolution_clock::time_point end_round = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end_round - begin_round;
        double time_round = duration.count();
        Round_time[round].push_back(time_round);
    }
    ok = ctx.IsFinished();
    if (!ok) {
        print_context_stack_if_failed(&ctx);
        return false;
    }

    return true;
}

string*base64_set[MAX_SIZE+1];
string*base64_set_p256[MAX_SIZE+1];

TEST(gg20, sign_t_n_mt) {
    string file_name_1 = IS_NN?"secp256k1_gg18_nn.txt":"secp256k1_gg18.txt";
    string file_name_2 = IS_NN?"p256_gg18_nn.txt":"p256_gg18.txt";
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
    std::cout << "TURNS:" << TURNS << std::endl;

    //sample SECP256k1
    std::cout << "SECP256K1:" << std::endl;
    double total_turn_round_time[MAX_SIZE-MIN_SIZE+1][ROUNDS];
    for(size_t i= 0;i<MAX_SIZE-MIN_SIZE+1;i++)
    {
        for(size_t j = 0;j<ROUNDS;j++)
        {
            total_turn_round_time[i][j] = 0;
        }
    }

    for (int t = 0; t < TURNS; t++) {

        double total_n_round_time[MAX_SIZE-MIN_SIZE+1][ROUNDS];

        for (int n = MIN_SIZE; n <= MAX_SIZE; n++) {
            const int N_PARTIES = n;
            double N = n;
            double half_n = ceil(N / 2);
            const int THRESHOLD = IS_NN?n:int(half_n);
            std::string party_ids[N_PARTIES];
            for (int i = 1; i <= n; i++) {
                string str = "co_signer" + std::to_string(i);
                party_ids[i - 1] = str;
            }
            std::vector<std::string> participants;
            for (int i = 1; i <= THRESHOLD; i++) {
                string str = "co_signer" + std::to_string(i);
                participants.push_back(str);
            }

            safeheron::bignum::BN m = BN("1234567812345678123456781234567812345678123456781234567812345678", 16);
            std::vector<std::future<bool> > res;
            res.resize(participants.size());
            std::string sign_key_base64_arr[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) {
                sign_key_base64_arr[i] = base64_set[N_PARTIES][i];
            }
            for (int i = 0; i < N_PARTIES; ++i) {
                map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
            }
            for (size_t i = 0; i < participants.size(); ++i) {
                res[i] = std::async(std::launch::async, sign, sign_key_base64_arr[i], participants, m, i);
            }
            for (size_t i = 0; i < participants.size(); ++i) {
                EXPECT_TRUE(res[i].get());
            }

            for(size_t i = 0;i< ROUNDS;i++) {
                double aver_time = vector_aver(Round_time[i]);
                total_n_round_time[n-5][i] = aver_time;
                Round_time[i].clear();
            }

        }
        for(size_t i=0;i<MAX_SIZE-MIN_SIZE+1;i++) {
            for (size_t j = 0; j < ROUNDS; j++) {
                total_turn_round_time[i][j]+=total_n_round_time[i][j];
            }
        }
    }

    for(size_t i= 0;i<MAX_SIZE-MIN_SIZE+1;i++)
    {
        printf("n=%zu\n",i+5);
        printf("sign time:%.9lf\n", sum_vector(total_turn_round_time[i],ROUNDS)/TURNS);
        for(size_t j = 0;j<ROUNDS;j++)
        {
            total_turn_round_time[i][j] = 0;
        }
        printf("\n");
    }

    //P256 sample
    std::cout << "P256:" << std::endl;

    for (int t = 0; t < TURNS; t++) {
        double total_n_round_time[MAX_SIZE-MIN_SIZE+1][ROUNDS];
        for (int n = MIN_SIZE; n <= MAX_SIZE; n++) {
            const int N_PARTIES = n;
            double N = n;
            double half_n = ceil(N / 2);
            const int THRESHOLD = IS_NN?n:int(half_n);
            std::string party_ids[N_PARTIES];
            for (int i = 1; i <= n; i++) {
                string str = "co_signer" + std::to_string(i);
                party_ids[i - 1] = str;
            }
            std::vector<std::string> participants;
            for (int i = 1; i <= THRESHOLD; i++) {
                string str = "co_signer" + std::to_string(i);
                participants.push_back(str);
            }

            safeheron::bignum::BN m = BN("1234567812345678123456781234567812345678123456781234567812345678",
                                         16);
            std::vector<std::future<bool> > res;
            res.resize(participants.size());
            std::string sign_key_base64_arr[N_PARTIES];
            for (int i = 0; i < N_PARTIES; i++) {
                sign_key_base64_arr[i] = base64_set_p256[N_PARTIES][i];
            }
            for (int i = 0; i < N_PARTIES; ++i) {
                map_id_message_queue[party_ids[i]] = PartyMessageQue<Msg>(ROUNDS);
            }
            for (size_t i = 0; i < participants.size(); ++i) {

                res[i] = std::async(std::launch::async, sign, sign_key_base64_arr[i], participants, m, i);
            }
            for (size_t i = 0; i < participants.size(); ++i) {
                EXPECT_TRUE(res[i].get());
            }
            for(size_t i = 0;i< ROUNDS;i++) {
                double aver_time = vector_aver(Round_time[i]);
                total_n_round_time[n-5][i] = aver_time;
                Round_time[i].clear();
            }
        }
        for(size_t i=0;i<MAX_SIZE-MIN_SIZE+1;i++) {
            for (size_t j = 0; j < ROUNDS; j++) {
                total_turn_round_time[i][j] += total_n_round_time[i][j];
            }
        }
    }
    for(size_t i= 0;i<MAX_SIZE-MIN_SIZE+1;i++)
    {
        printf("n=%zu\n",i+5);
        printf("sign time:%.9lf\n", sum_vector(total_turn_round_time[i],ROUNDS)/TURNS);
        printf("\n");

    }

    for (int i = 0; i < MAX_SIZE + 1; i++) {
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