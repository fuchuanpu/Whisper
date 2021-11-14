#pragma once

#include "../common.hpp"
#include "dpdkCommon.hpp"
#include "parserWorker.hpp"
#include "kMeansLearner.hpp"


#include <torch/torch.h>


namespace Whisper
{


struct PacketMetaData;
class ParserWorkerThread;
class KMeansLearner;
class DeviceConfig;


struct AnalyzerConfigParam final {

    // Number of fft
    size_t n_fft = 50;

    // Mean Window Train
    size_t mean_win_train = 50;
    // Mean Window Test
    size_t mean_win_test = 100;
    // Number of train sampling
    size_t num_train_sample = 50;

    // Save results to file
    bool save_to_file = false;
    // File path
    string save_dir = "";
    // File tag
    string save_file_prefix = "";

    // Verbose configure
    double_t verbose_interval = 5.0;
    bool init_verbose = false;
    bool mode_verbose = false;
    bool center_verbose = false;
    bool speed_verbose = false;
    bool ip_verbose = false;
    string verbose_ip_target = "";
    cpu_core_id_t verbose_center_core = 10;


    auto inline display_params() const -> void {
        printf("[Whisper Analyzer Configuration]\n");

        printf("ML realated param:\n");
        printf("Traing window size: %ld, Testing window size: %ld, Num. Training sample: %ld\n",
        mean_win_train, mean_win_test, num_train_sample);

        printf("Frequency domain analysis realated param:\n");
        printf("FFT component size: %ld\n", n_fft);

        if (save_to_file) {
            printf("Saving related param:\n");
            printf("Saving DIR: %s, Saving prefix: %s\n", 
            save_dir.c_str(), save_file_prefix.c_str());
        }

        stringstream ss;
        ss << "Verbose mode: {";
        if (init_verbose) ss << "Init,";
        if (mode_verbose) ss << "Mode,";
        if (center_verbose) ss << "Center,";
        if (speed_verbose) ss << "Speed,";
        if (ip_verbose) ss << "IP: " << verbose_ip_target;
        ss << "}";
        printf("%s (Interval %4.2lfs)\n\n", ss.str().c_str(), verbose_interval);

    }

    AnalyzerConfigParam() = default;
    virtual ~AnalyzerConfigParam() {}
    AnalyzerConfigParam & operator=(const AnalyzerConfigParam &) = delete;
    AnalyzerConfigParam(const AnalyzerConfigParam &) = delete;

};


class AnalyzerWorkerThread final : public pcpp::DpdkWorkerThread {

	friend class DeviceConfig;

private:

    // Indicator of stop
    volatile bool m_stop = false;
    // In training mode or testing mode
    bool m_is_train = true;
    // Core Id assigned by DPDK
    cpu_core_id_t m_core_id;

    // Index of per-packet properties array copied form Analyzer
    mutable size_t m_index = 0;
    // pause time for waitting analyzer (us)
    size_t pause_time = 50000;

	uint64_t analysis_pkt_len = 0;
	uint64_t analysis_pkt_num = 0;
	uint64_t sum_analysis_pkt_num = 0;
	uint64_t sum_analysis_pkt_len = 0;
	double_t analysis_start_time, analysis_end_time;

    // The buffer for fetched per-packet properties that are copied form ParserWorkers
    #define MAX_META_PKT_ARR_SIZE (1 << 25)
    size_t meta_pkt_arr_size = 2000000;
	shared_ptr<PacketMetaData[]> meta_pkt_arr;

// #define DETAIL_TIME_ANALYZE
// #define __DETAIL_TIME_ANALYZE

#ifdef DETAIL_TIME_ANALYZE
    double_t sum_weight_time = 0;
    double_t sum_dist_time = 0;
    double_t sum_transform_time = 0;
    double_t sum_aggregate_time = 0;
#ifdef __DETAIL_TIME_ANALYZE
    size_t analyze_entrance = 0;
#endif
#endif

    // The result of train, i.e. the clustring centers
    torch::Tensor centers;
    // KMeans Learner
    shared_ptr<KMeansLearner> p_learner;
    // The registed ParserWorkers
    vector<shared_ptr<ParserWorkerThread> > p_parser;
    // configuration
    shared_ptr<AnalyzerConfigParam> p_analyzer_config;
    
    // Result signature
    typedef struct {
        uint32_t address;
        double distence;
        size_t packet_num;
    } FlowRecord;

    // Memory to save results
    #define MAX_RES_BUF_SIZE (1 << 24)
    size_t result_buffer_size = 500000;
    size_t flow_record_size = 0;
    shared_ptr<FlowRecord[]> flow_records;

    const size_t max_fetch = 1 << 17;
    const double_t max_cluster_dist = 1e12;
    
    // Copy per-packet properties form registed ParserWorkers
    auto fetch_form_parser(const shared_ptr<ParserWorkerThread> pt) const -> size_t;
    // Extract Frequency Domain Representation from per-packet properties
    void wave_analyze();
    // Linear Tranformation of per-packet properties
    auto static inline weight_transform(const PacketMetaData & info) -> double_t;

public:

    AnalyzerWorkerThread(const vector<shared_ptr<ParserWorkerThread> > & _vp, 
                         const shared_ptr<KMeansLearner> _pl) : p_parser(_vp), p_learner(_pl) {}

    AnalyzerWorkerThread(const vector<shared_ptr<ParserWorkerThread> > & _vp, 
                         const shared_ptr<KMeansLearner> _pl,
                         const json & _j) : p_parser(_vp), p_learner(_pl) {
                             configure_via_json(_j);
                         }

    virtual ~AnalyzerWorkerThread() {}
    AnalyzerWorkerThread & operator=(const AnalyzerWorkerThread &) = delete;
    AnalyzerWorkerThread(const AnalyzerWorkerThread &) = delete;

    virtual bool run(uint32_t coreId) override;

    virtual void stop() override;

	virtual uint32_t getCoreId() const override {
		return m_core_id;
	}

    // Config form json file
    auto configure_via_json(const json & jin) -> bool;

    // Save result to json file
    auto save_res_json() const -> bool;

    auto get_overall_performance() const -> pair<double_t, double_t>;

};


}

