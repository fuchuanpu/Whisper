#pragma once


#include "parserWorker.hpp"
#include "kMeansLearner.hpp"
#include "analyzerWorker.hpp"
#include "dpdkCommon.hpp"


#define DISP_PARAM


namespace Whisper
{


class ParserWorkerThread;
class AnalyzerWorkerThread;
class KMeansLearner;


struct DeviceConfigParam final {
    // Number of NIC input and output queue
    nic_queue_id_t number_rx_queue = 8;
    nic_queue_id_t number_tx_queue = 8;
    mem_pool_size_t mbuf_pool_size = 4096 * 4 - 1;

    // DPDK CPU core config
    cpu_core_id_t core_use_for_analyze = 8;
    cpu_core_id_t core_use_for_parser = 8;
    cpu_core_id_t core_num = 17;

    vector<nic_port_id_t> dpdk_port_vec;

    auto inline display_params() const -> void {
        printf("[Whisper Device Configuration]\n");

        printf("Num. NIC RX queue: %d, Num. NIC TX queue: %d, NIC Mbuf pool size: %d.\n",
        number_rx_queue, number_tx_queue, mbuf_pool_size);

        stringstream ss;
        ss << "Used NIC Port for DPDK: [";
        for (const auto & id : dpdk_port_vec) {
            ss << static_cast<int>(id) << ", ";
        }
        ss << "]";
        printf("%s\n", ss.str().c_str());
        
        printf("Num. Core packet parsing: %d, Num. Core analyze: %d. [Sum core used: %d]\n\n"
        , core_use_for_analyze, core_use_for_parser, core_num);
    }

    DeviceConfigParam() {}
    virtual ~DeviceConfigParam() {}
    DeviceConfigParam & operator=(const DeviceConfigParam &) = delete;
    DeviceConfigParam(const DeviceConfigParam &) = delete;
};


struct ThreadStateManagement final {

	bool stop = true;

	vector<shared_ptr<ParserWorkerThread> > parser_worker_thread_vec;
    vector<shared_ptr<AnalyzerWorkerThread> > analyzer_worker_thread_vec;

	ThreadStateManagement() = default;
    virtual ~ThreadStateManagement() {}
    ThreadStateManagement & operator=(const ThreadStateManagement &) = default;
    ThreadStateManagement(const ThreadStateManagement &) = default;

    ThreadStateManagement(const decltype(parser_worker_thread_vec) & _p_vec,
                          const decltype(analyzer_worker_thread_vec) & _a_vec): 
                          parser_worker_thread_vec(_p_vec), analyzer_worker_thread_vec(_a_vec), stop(false) {}

};


class DeviceConfig final {
    
private:

    using device_list_t = vector<DpdkDevice*>;
    using assign_queue_t = vector<shared_ptr<DpdkConfig> >;

    shared_ptr<const DeviceConfigParam> p_configure_param;

    // Show configuration details
    bool verbose = true;
    mutable bool dpdk_init_once = false;

    // 3 helper for do_init
    auto configure_dpdk_nic(const CoreMask mask_all_used_core) const -> device_list_t;

    auto assign_queue_to_parser(const device_list_t & dev_list, 
					            const vector<SystemCore> & cores_parser) const -> assign_queue_t;

    auto create_worker_threads(const assign_queue_t & queue_assign,
                            vector<shared_ptr<ParserWorkerThread> > & parser_thread_vec,
                            vector<shared_ptr<AnalyzerWorkerThread> > & analyzer_thread_vec) -> bool;

    static void interrupt_callback(void* cookie);

    json j_cfg_analyzer;
    json j_cfg_kmeans;
    json j_cfg_parser;

public:
    
    // Default constructor
    explicit DeviceConfig() {
        LOGF("Device configure uses default parameters");
    }

    explicit DeviceConfig(const decltype(p_configure_param) _p): p_configure_param(_p) {
        LOGF("Device configure uses specific parameters");
    }

    explicit DeviceConfig(const json & jin) {
        if (configure_via_json(jin)) {
            LOGF("Device configure uses json");
        } else {
            LOGF("Json object invalid");
        }
    }

    virtual ~DeviceConfig() {};
    DeviceConfig & operator=(const DeviceConfig &) = delete;
    DeviceConfig(const DeviceConfig &) = delete;

    // List all of avaliable DPDK ports
    void list_dpdk_ports() const;

    // Do init after all configures are done
    void do_init();

    // Config form json file
    auto configure_via_json(const json & jin) -> bool;
};

}