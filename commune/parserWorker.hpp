#pragma once

#include "dpdkCommon.hpp"
#include "deviceConfig.hpp"
#include "analyzerWorker.hpp"


using namespace std;
using namespace pcpp;

namespace Whisper
{


class AnalyzerWorkerThread;
class DeviceConfig;


struct ParserConfigParam final {

	using verbose_mode_t = uint8_t;
	enum verbose_type : verbose_mode_t {
		NONE 	= 0x0,
		TRACING = 0x1,
		SUMMARY = 0x2,
		INIT 	= 0x4,
		ALL 	= 0x7
	};

	double_t verbose_interval = 5.0;
	verbose_mode_t verbose_mode = NONE;

	#define META_PKT_ARR_LIN (1 << 25)
	size_t meta_pkt_arr_size = 1000000;
	#define RECEIVE_BURST_LIM (1 << 16)
	size_t max_receive_burts = 64;

	ParserConfigParam() = default;
    virtual ~ParserConfigParam() {}
    ParserConfigParam & operator=(const ParserConfigParam &) = delete;
    ParserConfigParam(const ParserConfigParam &) = delete;

	auto inline display_params() const -> void {
        printf("[Whisper Parser Configuration]\n");

        printf("Memory realated param:\n");
        printf("Maximum receive burst: %ld, Meta data buffer size: %ld\n",
        max_receive_burts, meta_pkt_arr_size);

        stringstream ss;
        ss << "Verbose mode: {";
        if (verbose_mode & INIT) ss << "Init,";
        if (verbose_mode & TRACING) ss << "Tracing,";
        if (verbose_mode & SUMMARY) ss << "Summary,";
        ss << "}";
        printf("%s (Interval %4.2lfs)\n\n", ss.str().c_str(), verbose_interval);
        
    }
};

static const map<string, ParserConfigParam::verbose_type> verbose_mode_map = {
	{"tracing", 	ParserConfigParam::verbose_type::TRACING}, 
	{"summarizing", ParserConfigParam::verbose_type::SUMMARY}, 
	{"init", 		ParserConfigParam::verbose_type::INIT}, 
	{"complete", 	ParserConfigParam::verbose_type::ALL}
};


class ParserWorkerThread final : public DpdkWorkerThread {

	friend class AnalyzerWorkerThread;
	friend class DeviceConfig;

private:

	const shared_ptr<DpdkConfig> p_dpdk_config;
	shared_ptr<ParserConfigParam> p_parser_config;

	mutable bool m_stop = false;

	const cpu_core_id_t m_core_id;

	// statistical variables
	mutable vector<uint64_t> parsed_pkt_len;
	mutable vector<uint64_t> parsed_pkt_num;
	mutable vector<uint64_t> sum_parsed_pkt_num;
	mutable vector<uint64_t> sum_parsed_pkt_len;
	mutable double_t parser_start_time, parser_end_time;

	void verbose_final() const;
	void verbose_tracing_thread() const;

	// Read-Write exclution for per-packet Metadata
	mutable sem_t semaphore;
	void inline acquire_semaphore() const {
		sem_wait(&semaphore);
	}
	void inline release_semaphore() const {
		sem_post(&semaphore);
	}

	enum type_identify_mp : uint16_t {
		TYPE_TCP_SYN 	= 1,
		TYPE_TCP_FIN 	= 40,
		TYPE_TCP_RST 	= 1,
		TYPE_TCP_ACK 	= 1000,
		TYPE_TCP 		= 1000,
		TYPE_UDP 		= 3,
		TYPE_ICMP 		= 10,
		TYPE_IGMP 		= 9,
		TYPE_UNKNOWN 	= 10,
	};

	// Index of metadata array
	volatile size_t meta_index = 0;

public:

	// Collect the per-packets metadata
	shared_ptr<PacketMetaData[]> meta_pkt_arr;

	ParserWorkerThread(const shared_ptr<DpdkConfig> p_d, const json & j_p): 
					p_dpdk_config(p_d), m_core_id(p_d != nullptr ? p_d->core_id : MAX_NUM_OF_CORES + 1) {
		
		if (p_dpdk_config == nullptr) {
			FATAL_ERROR("NULL dpdk configuration for parser.");
		}

		sem_init(&semaphore, 0, 1);

		if (j_p.size()) {
			configure_via_json(j_p);
		}

		sum_parsed_pkt_num.resize(p_d->nic_queue_list.size(), 0);
		sum_parsed_pkt_len.resize(p_d->nic_queue_list.size(), 0);
		parsed_pkt_len.resize(p_d->nic_queue_list.size(), 0);
		parsed_pkt_num.resize(p_d->nic_queue_list.size(), 0);
    }

	ParserWorkerThread(const shared_ptr<DpdkConfig> p_d = nullptr, 
					   const shared_ptr<ParserConfigParam> p_p = nullptr): 
					p_dpdk_config(p_d), p_parser_config(p_p), 
					m_core_id(p_d != nullptr ? p_d->core_id : MAX_NUM_OF_CORES + 1) {

		if (p_dpdk_config == nullptr) {
			FATAL_ERROR("dpdk configuration not found for parser.");
		}

		sem_init(&semaphore, 0, 1);

		sum_parsed_pkt_num.resize(p_d->nic_queue_list.size(), 0);
		sum_parsed_pkt_len.resize(p_d->nic_queue_list.size(), 0);
		parsed_pkt_len.resize(p_d->nic_queue_list.size(), 0);
		parsed_pkt_num.resize(p_d->nic_queue_list.size(), 0);
	}

	virtual ~ParserWorkerThread() {}
	ParserWorkerThread & operator=(const ParserWorkerThread&) = delete;
	ParserWorkerThread(const ParserWorkerThread&) = delete;

	auto get_overall_performance() const -> pair<double_t, double_t>;

	virtual bool run(uint32_t coreId) override;

	virtual void stop() override {
		LOGF("Parser on core # %d stop.", getCoreId());
		m_stop = true;
		parser_end_time = get_time_spec();
		size_t index = 0;
		for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
			ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
				sum_parsed_pkt_num[index] += parsed_pkt_num[index];
				sum_parsed_pkt_len[index] += parsed_pkt_len[index];
				
				parsed_pkt_num[index] = 0;
				parsed_pkt_len[index] = 0;
				index ++;
		}
		verbose_final();
	}

	virtual uint32_t getCoreId() const override {
		return m_core_id;
	}

	auto configure_via_json(const json & jin) -> bool;

};

}
