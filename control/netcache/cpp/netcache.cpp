/* CREDITS:
This boiler plate code is heavily adapted from Intel Connectivity
Academy course ICA-1132: "Barefoot Runtime Interface & PTF"
*/

/* Standard Linux/C++ includes go here */
#include <bf_rt/bf_rt_common.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_session.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table_key.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <queue>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
/* All fixed function API includes go here */
#include <bf_switchd/bf_switchd.h>

#ifdef __cplusplus
}
#endif

/*
 * Convenient defines that reflect SDE conventions
 */
#ifndef SDE_INSTALL
#error "Please add -DSDE_INSTALL=\"$SDE_INSTALL\" to CPPFLAGS"
#endif

#ifndef PROG_NAME
#error "Please add -DPROG_NAME=\"netcache\" to CPPFLAGS"
#endif

#define CONF_FILE_DIR "share/p4/targets/tofino"
#define CONF_FILE_PATH(prog) \
    SDE_INSTALL "/" CONF_FILE_DIR "/" prog ".conf"

#define INIT_STATUS_TCP_PORT 7777
#define BFSHELL SDE_INSTALL "/bin/bfshell"  // macro string concat

#define DEV_TGT_ALL_PIPES 0xFFFF
#define DEV_TGT_ALL_PARSERS 0xFF
#define CHECK_BF_STATUS(status) __check_bf_status__(status, __FILE__, __LINE__)
bf_status_t status;

void __check_bf_status__(bf_status_t status, const char *file, int lineNumber);
std::vector<uint64_t> parse_string_to_key(std::string str);

struct message {
    long msg_type;
    uint32_t srcIP;
};

static inline bool sortAscByVal(const std::pair<uint64_t, uint64_t> &a, const std::pair<uint64_t, uint64_t> &b) {
    return (a.second < b.second);
}

int app_netcache(bf_switchd_context_t *switchd_ctx) {
    (void)switchd_ctx;
    bf_rt_target_t dev_tgt;
    std::shared_ptr<bfrt::BfRtSession> session;
    const bfrt::BfRtInfo *bf_rt_info = nullptr;
    auto fromHwFlag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;
    auto fromSwFlag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW;

    // to avoid unused compiler error
    printf("Flags - fromHwFlag=%ld, fromSwFlag=%ld\n",
           static_cast<uint64_t>(fromHwFlag), static_cast<uint64_t>(fromSwFlag));

    /* Adding ports and one-time config (whichever possible) via bfrt_python */
    // printf("\n\n****** Press enter to setup CPU-Eth ports... *****");
    // getchar();
    // printf("Configuring via bfrt_python script...\n");
    // fflush(stdout);
    // std::string bfshell_ports = BFSHELL " -f " __DIR__ "/../../bootstrap/port_setup";
    // system(bfshell_ports.c_str());

    // printf("\n\n****** Press enter to start Tofino Pktgen (port 68,?)... *****");
    // getchar();
    // printf("Configuring via bfrt_python script...\n");
    // fflush(stdout);
    // std::string bfshell_pktgen = BFSHELL " -b " __DIR__ "/../config_pktgen.py";
    // system(bfshell_pktgen.c_str());

    /* Prepare the dev_tgt */
    memset(&dev_tgt, 0, sizeof(dev_tgt));
    dev_tgt.dev_id = 0;
    dev_tgt.pipe_id = DEV_TGT_ALL_PIPES;

    /* Create BfRt session and retrieve BfRt Info */
    // Create a new BfRt session
    session = bfrt::BfRtSession::sessionCreate();
    if (session == nullptr) {
        printf("ERROR: Couldn't create BfRtSession\n");
        exit(1);
    }

    // Get ref to the singleton devMgr
    bfrt::BfRtDevMgr &dev_mgr = bfrt::BfRtDevMgr::getInstance();
    status = dev_mgr.bfRtInfoGet(dev_tgt.dev_id, PROG_NAME, &bf_rt_info);

    if (status != BF_SUCCESS) {
        printf("ERROR: Could not retrieve BfRtInfo: %s\n", bf_err_str(status));
        return status;
    }
    printf("Retrieved BfRtInfo successfully!\n");

    status = session->sessionCompleteOperations();
    CHECK_BF_STATUS(status);

    /**
     * NetCache's Implementation
     *
     * 1. Check packet generator's offset for every time interval
     *
     * 2. Cache Management
     *  a. Get heavy hitters from message queue, and select 256 items
     *  b. Evict 256 items (instruction) if table load > 0.9
     *  c. Insert 256 items (instruction)
     *  d. Flush them
     */

    // count-min
    const bfrt::BfRtTable *reg_cm0 = nullptr;
    const bfrt::BfRtTable *reg_cm1 = nullptr;
    const bfrt::BfRtTable *reg_cm2 = nullptr;
    const bfrt::BfRtTable *reg_cm3 = nullptr;
    // bloom filters
    const bfrt::BfRtTable *reg_bf0 = nullptr;
    const bfrt::BfRtTable *reg_bf1 = nullptr;
    const bfrt::BfRtTable *reg_bf2 = nullptr;
    // cache counters
    const bfrt::BfRtTable *reg_cch = nullptr;
    // cache table
    const bfrt::BfRtTable *cache_table = nullptr;

    // registers
    bf_rt_id_t reg_cm0_key_id, reg_cm1_key_id, reg_cm2_key_id, reg_cm3_key_id;      // cm's key
    bf_rt_id_t reg_cm0_data_id, reg_cm1_data_id, reg_cm2_data_id, reg_cm3_data_id;  // cm's val
    bf_rt_id_t reg_bf0_key_id, reg_bf1_key_id, reg_bf2_key_id;                      // bf's key
    bf_rt_id_t reg_bf0_data_id, reg_bf1_data_id, reg_bf2_data_id;                   // bf's val
    bf_rt_id_t reg_cch_key_id, reg_cch_data_id;                                     // cache counter's key and val

    // table
    bf_rt_id_t cache_table_srcip_field_id;
    bf_rt_id_t cache_hit_action_id;
    bf_rt_id_t cache_hit_idx_field_id;
    bf_rt_id_t cache_miss_action_id;

    // Objects
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_cm0", &reg_cm0);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_cm1", &reg_cm1);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_cm2", &reg_cm2);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_cm3", &reg_cm3);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_bf0", &reg_bf0);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_bf1", &reg_bf1);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_bf2", &reg_bf2);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.reg_cch", &reg_cch);
    CHECK_BF_STATUS(status);
    status = bf_rt_info->bfrtTableFromNameGet("Pipe1SwitchIngress.cache_table", &cache_table);
    CHECK_BF_STATUS(status);

    // Key/Action Fields ID(s)
    status = reg_cm0->keyFieldIdGet("$REGISTER_INDEX", &reg_cm0_key_id);
    CHECK_BF_STATUS(status);
    status = reg_cm0->dataFieldIdGet("Pipe1SwitchIngress.reg_cm0.f1", &reg_cm0_data_id);
    CHECK_BF_STATUS(status);
    status = reg_cm1->keyFieldIdGet("$REGISTER_INDEX", &reg_cm1_key_id);
    CHECK_BF_STATUS(status);
    status = reg_cm1->dataFieldIdGet("Pipe1SwitchIngress.reg_cm1.f1", &reg_cm1_data_id);
    CHECK_BF_STATUS(status);
    status = reg_cm2->keyFieldIdGet("$REGISTER_INDEX", &reg_cm2_key_id);
    CHECK_BF_STATUS(status);
    status = reg_cm2->dataFieldIdGet("Pipe1SwitchIngress.reg_cm2.f1", &reg_cm2_data_id);
    CHECK_BF_STATUS(status);
    status = reg_cm3->keyFieldIdGet("$REGISTER_INDEX", &reg_cm3_key_id);
    CHECK_BF_STATUS(status);
    status = reg_cm3->dataFieldIdGet("Pipe1SwitchIngress.reg_cm3.f1", &reg_cm3_data_id);
    CHECK_BF_STATUS(status);
    status = reg_bf0->keyFieldIdGet("$REGISTER_INDEX", &reg_bf0_key_id);
    CHECK_BF_STATUS(status);
    status = reg_bf0->dataFieldIdGet("Pipe1SwitchIngress.reg_bf0.f1", &reg_bf0_data_id);
    CHECK_BF_STATUS(status);
    status = reg_bf1->keyFieldIdGet("$REGISTER_INDEX", &reg_bf1_key_id);
    CHECK_BF_STATUS(status);
    status = reg_bf1->dataFieldIdGet("Pipe1SwitchIngress.reg_bf1.f1", &reg_bf1_data_id);
    CHECK_BF_STATUS(status);
    status = reg_bf2->keyFieldIdGet("$REGISTER_INDEX", &reg_bf2_key_id);
    CHECK_BF_STATUS(status);
    status = reg_bf2->dataFieldIdGet("Pipe1SwitchIngress.reg_bf2.f1", &reg_bf2_data_id);
    CHECK_BF_STATUS(status);
    status = reg_cch->keyFieldIdGet("$REGISTER_INDEX", &reg_cch_key_id);
    CHECK_BF_STATUS(status);
    status = reg_cch->dataFieldIdGet("Pipe1SwitchIngress.reg_cch.f1", &reg_cch_data_id);
    CHECK_BF_STATUS(status);
    status = cache_table->keyFieldIdGet("hdr.ipv4.src_addr", &cache_table_srcip_field_id);
    CHECK_BF_STATUS(status);
    status = cache_table->actionIdGet("Pipe1SwitchIngress.cache_hit", &cache_hit_action_id);
    CHECK_BF_STATUS(status);
    status = cache_table->dataFieldIdGet("idx", cache_hit_action_id, &cache_hit_idx_field_id);
    CHECK_BF_STATUS(status);
    status = cache_table->actionIdGet("Pipe1SwitchIngress.cache_miss", &cache_miss_action_id);
    CHECK_BF_STATUS(status);

    std::unique_ptr<bfrt::BfRtTableKey> reg_cm0_index, reg_cm1_index, reg_cm2_index, reg_cm3_index;
    std::unique_ptr<bfrt::BfRtTableData> reg_cm0_value, reg_cm1_value, reg_cm2_value, reg_cm3_value;
    std::unique_ptr<bfrt::BfRtTableKey> reg_bf0_index, reg_bf1_index, reg_bf2_index;
    std::unique_ptr<bfrt::BfRtTableData> reg_bf0_value, reg_bf1_value, reg_bf2_value;
    std::unique_ptr<bfrt::BfRtTableKey> reg_cch_index;
    std::unique_ptr<bfrt::BfRtTableData> reg_cch_value;
    std::unique_ptr<bfrt::BfRtTableKey> cache_table_key;
    std::unique_ptr<bfrt::BfRtTableData> cache_table_value;

    // allocate index and values
    status = reg_cm0->keyAllocate(&reg_cm0_index);
    CHECK_BF_STATUS(status);
    status = reg_cm0->dataAllocate(&reg_cm0_value);
    CHECK_BF_STATUS(status);
    status = reg_cm1->keyAllocate(&reg_cm1_index);
    CHECK_BF_STATUS(status);
    status = reg_cm1->dataAllocate(&reg_cm1_value);
    CHECK_BF_STATUS(status);
    status = reg_cm2->keyAllocate(&reg_cm2_index);
    CHECK_BF_STATUS(status);
    status = reg_cm2->dataAllocate(&reg_cm2_value);
    CHECK_BF_STATUS(status);
    status = reg_cm3->keyAllocate(&reg_cm3_index);
    CHECK_BF_STATUS(status);
    status = reg_cm3->dataAllocate(&reg_cm3_value);
    CHECK_BF_STATUS(status);

    status = reg_bf0->keyAllocate(&reg_bf0_index);
    CHECK_BF_STATUS(status);
    status = reg_bf0->dataAllocate(&reg_bf0_value);
    CHECK_BF_STATUS(status);
    status = reg_bf1->keyAllocate(&reg_bf1_index);
    CHECK_BF_STATUS(status);
    status = reg_bf1->dataAllocate(&reg_bf1_value);
    CHECK_BF_STATUS(status);
    status = reg_bf2->keyAllocate(&reg_bf2_index);
    CHECK_BF_STATUS(status);
    status = reg_bf2->dataAllocate(&reg_bf2_value);
    CHECK_BF_STATUS(status);

    status = reg_cch->keyAllocate(&reg_cch_index);
    CHECK_BF_STATUS(status);
    status = reg_cch->dataAllocate(&reg_cch_value);
    CHECK_BF_STATUS(status);


    // table
    status = cache_table->keyAllocate(&cache_table_key);
    CHECK_BF_STATUS(status);
    status = cache_table->dataAllocate(&cache_table_value);
    CHECK_BF_STATUS(status);

    // reset key and data
    status = reg_cm0->keyReset(reg_cm0_index.get());
    CHECK_BF_STATUS(status);
    status = reg_cm0->dataReset(reg_cm0_value.get());
    CHECK_BF_STATUS(status);
    status = reg_cm1->keyReset(reg_cm1_index.get());
    CHECK_BF_STATUS(status);
    status = reg_cm1->dataReset(reg_cm1_value.get());
    CHECK_BF_STATUS(status);
    status = reg_cm2->keyReset(reg_cm2_index.get());
    CHECK_BF_STATUS(status);
    status = reg_cm2->dataReset(reg_cm2_value.get());
    CHECK_BF_STATUS(status);
    status = reg_cm3->keyReset(reg_cm3_index.get());
    CHECK_BF_STATUS(status);
    status = reg_cm3->dataReset(reg_cm3_value.get());
    CHECK_BF_STATUS(status);

    status = reg_bf0->keyReset(reg_bf0_index.get());
    CHECK_BF_STATUS(status);
    status = reg_bf0->dataReset(reg_bf0_value.get());
    CHECK_BF_STATUS(status);
    status = reg_bf1->keyReset(reg_bf1_index.get());
    CHECK_BF_STATUS(status);
    status = reg_bf1->dataReset(reg_bf1_value.get());
    CHECK_BF_STATUS(status);
    status = reg_bf2->keyReset(reg_bf2_index.get());
    CHECK_BF_STATUS(status);
    status = reg_bf2->dataReset(reg_bf2_value.get());
    CHECK_BF_STATUS(status);

    status = reg_cch->keyReset(reg_cch_index.get());
    CHECK_BF_STATUS(status);
    status = reg_cch->dataReset(reg_cch_value.get());
    CHECK_BF_STATUS(status);

    status = cache_table->keyReset(cache_table_key.get());
    CHECK_BF_STATUS(status);
    status = cache_table->dataReset(cache_hit_action_id, cache_table_value.get());
    CHECK_BF_STATUS(status);

    /* global variables to manage cache */
    const uint64_t cacheSize = 65536; // 64K entries
    const uint64_t targetCacheSize = uint64_t(65536 * 0.9); // table load factor 0.9
    const uint64_t batchSize = 256; // batch replacement size

    // std::ofstream outfile("netcache.log");
    std::vector<uint64_t> hhVector;                           // HH reports from data plane
    std::unordered_map<uint64_t, uint64_t> cchTableKeyToIdx;  // key -> cch_index
    std::vector<uint64_t> cchTableKeyVec;                     // key vector for fast sampling

    // cache table's index (manually allocated)
    std::vector<uint64_t> cacheTableResidualIdx;
    for (size_t i = 0; i < cacheSize; i++)
        cacheTableResidualIdx.push_back(i);

    // random generator
    std::random_device rd;                                         // obtain a random number from hardware
    std::mt19937 gen(rd());                                        // seed the generator
    std::uniform_int_distribution<> distr(0, uint32_t(20000000));  // define the range

    // message queue
    key_t key = 12345; // must be same with netcacheHH.c
    int msqid;
    struct message msg;
    if ((msqid = msgget(key, IPC_CREAT | 0666)) == -1) {
        printf("msgget failed\n");
        exit(0);
    }
    printf("Message Queue msqid: %d\n", msqid);

    std::vector<uint64_t> reg_data_vector;
    auto del_last = std::chrono::system_clock::now();
    while (true) {
        status = session->sessionCompleteOperations();
        CHECK_BF_STATUS(status);
        auto now = std::chrono::system_clock::now();

        status = session->sessionCompleteOperations();
        CHECK_BF_STATUS(status);

        // refresh all values for one second
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - del_last);
        auto ms = milliseconds.count();
        
        if (ms > 1000) {
            // every second, we clean all CM and BF as described in the paper
            status = reg_cm0->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_cm1->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_cm2->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_cm3->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_bf0->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_bf1->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = reg_bf2->tableClear(*session, dev_tgt);
            CHECK_BF_STATUS(status);
            status = session->sessionCompleteOperations();
            CHECK_BF_STATUS(status);
            del_last = std::chrono::system_clock::now();

            // clean message queue
            while (msgrcv(msqid, &msg, sizeof(uint32_t), 0, IPC_NOWAIT) != -1) {
            }
            hhVector.clear();
            // printf("*** Refreshed *****\n");
        }

        // get messages of HH
        for (int i = 0; i < 10000; ++i) {
            if (msgrcv(msqid, &msg, sizeof(uint32_t), 0, IPC_NOWAIT) == -1)
                break;
            hhVector.push_back(static_cast<uint64_t>(msg.srcIP));
        }

        // if no candidates, restart the loop
        if (hhVector.empty())
            continue;

        // pick up at most 256 keys which are not in cache
        std::vector<uint64_t> keyToInsert;
        while (true) {
            if (keyToInsert.size() >= batchSize)
                break;

            // // get "recently reported" key --> gives a poor performance
            // auto key = hhVector.back();
            // hhVector.pop_back();

            // get "least recently reported" key
            auto key = hhVector.front();
            hhVector.erase(hhVector.begin());

            // if not in cache table, accept
            if (cchTableKeyToIdx.find(key) == cchTableKeyToIdx.end())
                keyToInsert.push_back(key);

            // if no more candidate, stop
            if (hhVector.empty())
                break;
        }

        // if table load is over 0.9, then evict a batch (e.g., 256) of items
        if (cchTableKeyToIdx.size() > targetCacheSize) {
            assert(cchTableKeyVec.size() == cchTableKeyToIdx.size());

            // randomly sample 4K items
            auto start_point = std::min(uint32_t(rand() % cchTableKeyVec.size()), uint32_t(cchTableKeyVec.size() - 4097));
            std::vector<uint64_t> keyToEvictVec(cchTableKeyVec.begin() + start_point, cchTableKeyVec.begin() + start_point + 4096);

            // get counters and pick bottom-256 items
            std::vector<std::pair<uint64_t, uint64_t>> sortedEvictVector;  // (key, counter)
            for (const auto &key : keyToEvictVec) {
                // read counter from ASIC
                reg_data_vector.clear();
                auto cchIdx = cchTableKeyToIdx[key];
                status = reg_cch_index->setValue(reg_cch_key_id, static_cast<uint64_t>(cchIdx));
                CHECK_BF_STATUS(status);  // set index to read
                status = reg_cch->dataReset(reg_cch_value.get());
                CHECK_BF_STATUS(status);
                status = reg_cch->tableEntryGet(*session, dev_tgt, *reg_cch_index, fromHwFlag, reg_cch_value.get());
                CHECK_BF_STATUS(status);
                status = reg_cch_value->getValue(reg_cch_data_id, &reg_data_vector);
                CHECK_BF_STATUS(status);                                               // dump to user-program
                sortedEvictVector.push_back(std::make_pair(key, reg_data_vector[0]));  // first of reg-pair
            }
            std::sort(sortedEvictVector.begin(), sortedEvictVector.end(), sortAscByVal);  // begin() : smallest
            sortedEvictVector.resize(batchSize);

            // evict from table
            status = session->beginBatch();
            CHECK_BF_STATUS(status);
            for (const auto &kvpair : sortedEvictVector) {
                status = cache_table->keyReset(cache_table_key.get());
                status = cache_table_key->setValue(cache_table_srcip_field_id, kvpair.first);
                CHECK_BF_STATUS(status);
                status = cache_table->tableEntryDel(*session, dev_tgt, *cache_table_key);
                CHECK_BF_STATUS(status);
            }
            status = session->flushBatch();
            CHECK_BF_STATUS(status);
            status = session->endBatch(true);
            CHECK_BF_STATUS(status);
            status = session->sessionCompleteOperations();
            CHECK_BF_STATUS(status);

            // update C++ API's local variables (i.e., remove the evicted items)
            for (const auto &kvpair : sortedEvictVector) {
                auto cchIdx = cchTableKeyToIdx[kvpair.first];
                cacheTableResidualIdx.push_back(cchIdx);  // restore the index
                cchTableKeyToIdx.erase(kvpair.first);
                cchTableKeyVec.erase(std::find(cchTableKeyVec.begin(), cchTableKeyVec.end(), kvpair.first));
            }
        }

        // insert a batch of items
        uint32_t nInsert = 0;
        for (const auto &key : keyToInsert) {
            status = cache_table->keyReset(cache_table_key.get());
            CHECK_BF_STATUS(status);
            status = cache_table_key->setValue(cache_table_srcip_field_id, key);
            CHECK_BF_STATUS(status);
            auto cache_counter_idx = cacheTableResidualIdx.front();
            status = cache_table_value->setValue(cache_hit_idx_field_id, cache_counter_idx);
            CHECK_BF_STATUS(status);
            status = cache_table->tableEntryAdd(*session, dev_tgt, *cache_table_key, *cache_table_value);
            if (status != BF_SUCCESS)
                continue;  // failed to insert, so pass
            nInsert++;
            status = session->sessionCompleteOperations();
            CHECK_BF_STATUS(status);

            // update C++ API's local variables
            cacheTableResidualIdx.erase(cacheTableResidualIdx.begin());
            cchTableKeyToIdx.insert(std::make_pair(key, cache_counter_idx));
            cchTableKeyVec.push_back(key);
        }
        status = session->sessionCompleteOperations();
        CHECK_BF_STATUS(status);
    }

    // printf("\n\n *** Press any key to exit... *** \n");
    // getchar();

    // /* Run Indefinitely */
    // printf("Run indefinitely...\n");
    // while (true) {
    //     sleep(1);
    // }

    status = session->sessionDestroy();
    CHECK_BF_STATUS(status);
    return status;
}

/* Helper function to check bf_status */
void __check_bf_status__(bf_status_t status, const char *file, int lineNumber) {
    ;
    if (status != BF_SUCCESS) {
        printf("ERROR: CHECK_BF_STATUS failed at %s:%d\n", file, lineNumber);
        printf("   ==> with error: %s\n", bf_err_str(status));
        exit(status);
    }
}

bf_switchd_context_t *init_switchd() {
    bf_status_t status = 0;
    bf_switchd_context_t *switchd_ctx;

    /* Allocate switchd context */
    if ((switchd_ctx = (bf_switchd_context_t *)calloc(
             1, sizeof(bf_switchd_context_t))) == NULL) {
        printf("Cannot Allocate switchd context\n");
        exit(1);
    }

    /* Minimal switchd context initialization to get things going */
    switchd_ctx->install_dir = strdup(SDE_INSTALL);
    switchd_ctx->conf_file = strdup(CONF_FILE_PATH(PROG_NAME));
    switchd_ctx->running_in_background = true;
    switchd_ctx->dev_sts_thread = true;
    switchd_ctx->dev_sts_port = INIT_STATUS_TCP_PORT;

    /* Initialize the device */
    status = bf_switchd_lib_init(switchd_ctx);
    if (status != BF_SUCCESS) {
        printf("ERROR: Device initialization failed: %s\n", bf_err_str(status));
        exit(1);
    }

    return switchd_ctx;
}

int main(int argc, char **argv) {
    /* Not using cmdline params in this minimal boiler plate */
    (void)argc;
    (void)argv;

    bf_status_t status = 0;
    bf_switchd_context_t *switchd_ctx;

    /* Check if this CP program is being run as root */
    if (geteuid() != 0) {
        printf("ERROR: This control plane program must be run as root (e.g. sudo %s)\n", argv[0]);
        exit(1);
    }

    /* Initialize the switchd context */
    switchd_ctx = init_switchd();

    status = app_netcache(switchd_ctx);
    CHECK_BF_STATUS(status);

    if (switchd_ctx) {
        free(switchd_ctx);
    }
    return status;
}
