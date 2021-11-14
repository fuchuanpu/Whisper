#include "deviceConfig.hpp"
#include "parserWorker.hpp"

using namespace Whisper;
using namespace pcpp;


void DeviceConfig::list_dpdk_ports() const 
{
	if (verbose) {
		LOGF("Display DPDK device info.");
	}

	CoreMask core_mask_use;
	if (p_configure_param->core_num <= 1) {
		core_mask_use = getCoreMaskForAllMachineCores();
	} else {
		core_mask_use = (1 << p_configure_param->core_num) - 1;
	}
	
	printf("----- Display DPDK setting -----\n");
	if (dpdk_init_once) {
		LOGF("DPDK has init.");
	} else {
		if (!DpdkDeviceList::initDpdk(core_mask_use, p_configure_param->mbuf_pool_size)) {
			FATAL_ERROR("couldn't initialize DPDK");
		} else {
			dpdk_init_once = true;
		}
	}

	printf("DPDK port list:\n");

	const auto device_list = DpdkDeviceList::getInstance().getDpdkDeviceList();
	for(const auto p_dev: device_list) {
		decltype(p_dev) dev = p_dev;
		printf("DPDK Port #%d: MAC address='%s'; PCI address='%s'; Interface Drive='%s'\n",
				dev->getDeviceId(),
				dev->getMacAddress().toString().c_str(),
				dev->getPciAddress().c_str(),
				dev->getPMDName().c_str());
	}
}


auto DeviceConfig::assign_queue_to_parser(const device_list_t & dev_list, 
											const vector<SystemCore> & cores_parser) const -> assign_queue_t 
{
	if (verbose) {
		LOGF("Assign NIC queue to packer parsering threads.");
	}

	nic_queue_id_t total_number_que = 0;
	using nic_queue_rep_t = vector<pair<device_list_t::value_type, nic_queue_id_t> >;
	nic_queue_rep_t que_to_use;
	for (const auto p_dev: dev_list) {
		for (nic_queue_id_t i = 0; i < p_configure_param->number_rx_queue; i ++ ) {
			que_to_use.push_back({p_dev, i});
		}
		total_number_que += p_configure_param->number_rx_queue;
	}

	nic_queue_rep_t temp(que_to_use);
	que_to_use.clear();
	for (nic_queue_id_t i = 0; i < p_configure_param->number_rx_queue; i ++) {
		for(nic_port_id_t j = 0; j < dev_list.size(); j ++) {
			que_to_use.push_back(temp[j * p_configure_param->number_rx_queue + i]);
		}
	}
	nic_queue_id_t num_rx_queues_percore = total_number_que / cores_parser.size();
	nic_queue_id_t rx_queues_remainder = total_number_que % cores_parser.size();

	nic_queue_rep_t::const_iterator ite_to_assign = que_to_use.cbegin();
	assign_queue_t _assignment;
	for (const auto & _core: cores_parser) {
		printf("Using core %d for parsering.\n", _core.Id);

		auto _config = make_shared<DpdkConfig>();
		_config->core_id = _core.Id;
		for (nic_queue_id_t index = 0; index < num_rx_queues_percore; index++) {
			if (ite_to_assign == que_to_use.cend()) {
				break;
			}
			_config->nic_queue_list[ite_to_assign->first].push_back(ite_to_assign->second);
			ite_to_assign ++;
		}

		if (rx_queues_remainder > 0 && (ite_to_assign != que_to_use.cend())) {
			_config->nic_queue_list[ite_to_assign->first].push_back(ite_to_assign->second);
			ite_to_assign ++;

			rx_queues_remainder --;
		}

		_assignment.push_back(_config);
		printf("Core configuration:\n");
		for (const auto & ref: _config->nic_queue_list) {
			printf("\t DPDK device#%d: ", ref.first->getDeviceId());
			for (const auto v: ref.second) {
				printf("\t RX-Queue#%d;  ", v);
			}
			printf("\n");
		}
		if (_config->nic_queue_list.size() == 0) {
			printf("\t None\n");
		}
	}
	return _assignment;
}


auto DeviceConfig::create_worker_threads(const assign_queue_t & queue_assign,
						vector<shared_ptr<ParserWorkerThread> > & parser_thread_vec,
						vector<shared_ptr<AnalyzerWorkerThread> > & analyzer_thread_vec) -> bool
{

#ifdef DISP_PARAM
	if (verbose) {
		p_configure_param->display_params();
	}
#endif

	for (size_t i = 0; i < p_configure_param->core_use_for_parser; i ++) {
		const auto p_new_parser = make_shared<ParserWorkerThread>(queue_assign[i]);

		parser_thread_vec.push_back(p_new_parser);

		if (j_cfg_parser.size() != 0) {
			p_new_parser->configure_via_json(j_cfg_parser);
		}
	}

#ifdef DISP_PARAM
	if (verbose) {
		parser_thread_vec[0]->p_parser_config->display_params();
	}
#endif

	size_t parser_per_analyzer = parser_thread_vec.size() / 
				(size_t) p_configure_param->core_use_for_analyze;
	
	size_t parser_remain = parser_thread_vec.size() - 
				((size_t) p_configure_param->core_use_for_analyze * parser_per_analyzer);
	
	using ptr_vec_for_parser = vector<shared_ptr<ParserWorkerThread> >;
	vector<ptr_vec_for_parser> ve_all;
	for (cpu_core_id_t i = 0; i < p_configure_param->core_use_for_analyze; i ++) {
		ptr_vec_for_parser ve(parser_thread_vec.begin() + ( i		* parser_per_analyzer), 
							  parser_thread_vec.begin() + ((i + 1) * parser_per_analyzer));
		ve_all.push_back(ve);
	}

	assert(parser_remain <= ve_all.size());
	for (int i = 0; i < parser_remain; i ++) {
		ve_all[i].push_back(parser_thread_vec[parser_thread_vec.size() - i - 1]);
	}

	// Create KMeansLearner for Analyzer
	const auto & p_k_learner = make_shared<KMeansLearner>();
	if (p_k_learner == nullptr) {
		return false;
	}
	if (j_cfg_kmeans.size() != 0) {
		p_k_learner->configure_via_json(j_cfg_kmeans);
	}
#ifdef DISP_PARAM
	if (verbose) {
		p_k_learner->p_learner_config->display_params();
	}
#endif

	// bind the KMeans Learner and the ParserWorkers to the AnalyzeWorker
	for (cpu_core_id_t i = 0; i < p_configure_param->core_use_for_analyze; i ++) {
		const auto p_new_analyzer = make_shared<AnalyzerWorkerThread>(ve_all[i], p_k_learner);
		if (p_new_analyzer == nullptr) {
			return false;
		}
		// use json config first
		if (j_cfg_analyzer.size() != 0) {
			p_new_analyzer->configure_via_json(j_cfg_analyzer);
		}

		analyzer_thread_vec.push_back(p_new_analyzer);
	}

#ifdef DISP_PARAM
	if (verbose) {
		analyzer_thread_vec[0]->p_analyzer_config->display_params();
	}
#endif

	return true;
}


void DeviceConfig::interrupt_callback(void* cookie) 
{
	ThreadStateManagement * args = (ThreadStateManagement *) cookie;

	printf("\n ----- Whisper stopped ----- \n");

	// stop worker threads
	DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
	usleep(5000);
	DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
	usleep(5000);
	DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

	// print final stats for every worker thread plus sum of all threads and free worker threads memory
	double_t overall_parser_num = 0, overall_parser_len = 0;
	bool __is_print_parser = false;
	for (auto & _p_thread: args->parser_worker_thread_vec) {
		const auto ref = _p_thread->get_overall_performance();
		overall_parser_num += ref.first;
		overall_parser_len += ref.second;
		if (_p_thread->p_parser_config->verbose_mode & _p_thread->p_parser_config->SUMMARY) {
			__is_print_parser = true;
		}
	}
	if (__is_print_parser) {
		LOGF("Parser Overall Performance: [%4.2lf Mpps / %4.2lf Gbps]", overall_parser_num, overall_parser_len);
	}

#ifndef START_PARSER_ONLY
	double_t overall_analyzer_num = 0, overall_analyzer_len = 0;
	bool __is_print_analyzer = false;
	for (auto & _p_thread: args->analyzer_worker_thread_vec) {
		const auto ref = _p_thread->get_overall_performance();
		overall_analyzer_num += ref.first;
		overall_analyzer_len += ref.second;
		if (_p_thread->p_analyzer_config->speed_verbose) {
			__is_print_analyzer = true;
		}
	}
	if (__is_print_analyzer) {
		LOGF("Analyzer Overall Performance: [%4.2lf Mpps / %4.2lf Gbps]", overall_analyzer_num, overall_analyzer_len);
	}
#endif

	args->stop = true;
}


auto DeviceConfig::configure_dpdk_nic(const CoreMask mask_all_used_core) const -> device_list_t 
{
	LOGF("Init DPDK device.");

	// initialize DPDK
	if (dpdk_init_once) {
		LOGF("DPDK has already init.");
	} else {
		if (!DpdkDeviceList::initDpdk(mask_all_used_core, p_configure_param->mbuf_pool_size)) {
			FATAL_ERROR("Couldn't initialize DPDK.");
		} else {
			dpdk_init_once = true;
		}
	}

	// removing DPDK master core from core mask because DPDK worker threads cannot run on master core
	CoreMask core_mask_remain = mask_all_used_core & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);


	// collect the list of DPDK devices
	device_list_t device_to_use;
	for (const auto dpdk_port: p_configure_param->dpdk_port_vec) {
		const auto p_dev = DpdkDeviceList::getInstance().getDeviceByPort(dpdk_port);
		if (p_dev == nullptr) {
			FATAL_ERROR("Couldn't initialize DPDK device.");
		}
		// DpdkDevice::LinkStatus _stat;
		// p_dev->getLinkStatus(_stat);
		// if (!_stat.linkUp) {
		// 	FATAL_ERROR("DPDK device down.");
		// }
		device_to_use.push_back(p_dev);
	}

	// go over all devices and open them
	for (const auto & p_dev: device_to_use) {
		if (p_dev->getTotalNumOfRxQueues() < p_configure_param->number_rx_queue) {
			WARN("Number of requeired receive queue exceeds (%d) NIC support (%d).", 
					p_configure_param->number_rx_queue, p_dev->getTotalNumOfRxQueues());
			FATAL_ERROR("Device opening fail.");
		}
		if (p_dev->getTotalNumOfTxQueues() < p_configure_param->number_tx_queue) {
			WARN("Number of requeired transit queue exceeds (%d) NIC support (%d).", 
					p_configure_param->number_tx_queue, p_dev->getTotalNumOfTxQueues());
			FATAL_ERROR("Device opening fail.");
		}

		DpdkDevice::DpdkDeviceConfiguration dev_cfg;
// #define RSS_BETTER_BALANCE
#ifdef RSS_BETTER_BALANCE
		dev_cfg.rssKey = nullptr;
		dev_cfg.rssKeyLength = 0;
		dev_cfg.rssHashFunction = -1;
#endif
		if (p_dev->openMultiQueues(p_configure_param->number_rx_queue, p_configure_param->number_tx_queue, dev_cfg)) {
			LOGF("Device open %s success.", p_dev->getDeviceName().c_str());
		} else {
			FATAL_ERROR("Device opening fail.");
		}
	}
	
	return device_to_use;
}


void DeviceConfig::do_init() {

	LOGF("Configure Whisper runtime environment.");

	static const auto _f_check_device_configure_param = [] (decltype(p_configure_param) p_param)-> bool {
		if (!p_param) {
			WARN("Configure struct not found.");
			return false;
		}
		if (p_param->dpdk_port_vec.empty()) {
			WARN("DPDK port list is empty.");
			return false;
		}

		CoreMask all_core_mask = getCoreMaskForAllMachineCores();
		vector<SystemCore> all_core;
		createCoreVectorFromCoreMask(all_core_mask, all_core);
		size_t all_core_num = all_core.size();

		if (all_core_num < p_param->core_num) {
			WARN("Exceed all system core number.");
			return false;
		}
		if (MAX_NUM_OF_CORES < p_param->core_num) {
			WARN("Exceed maximum core number Libpcapplusplus supported.");
			return false;
		}
		if (p_param->core_num < 2) {
			WARN("Needed minimum of 2 cores to start the application.");
			return false;
		}
		if (p_param->core_num < p_param->core_use_for_analyze + p_param->core_use_for_parser) {
			WARN("Core number conflicts.");
			return false;
		}
		if (p_param->core_use_for_analyze % p_param->core_use_for_parser != 0) {
			WARN("Imbalanced core numbers for analyzer and parser.");
			return false;
		}
		return true;
	};

	if (!_f_check_device_configure_param(p_configure_param)) {
		FATAL_ERROR("Configure is invalid.");
	}

	// configure PcapPlusPlus Log Error Level
	LoggerPP::getInstance().suppressErrors();

	// use 1 core for DPDK master and 17 cores for workers
	vector<SystemCore> cores_to_use;
	CoreMask core_mask_to_use = (1 << p_configure_param->core_num) - 1;

	// configure DPDK
	const auto device_list = this->configure_dpdk_nic(core_mask_to_use);

	// prepare configuration for every core
	CoreMask core_without_master = core_mask_to_use & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);
	CoreMask core_mask_parser = core_without_master & ((1 << (1 + p_configure_param->core_use_for_analyze)) - 1);
	CoreMask core_mask_analyzer = core_without_master & ~core_mask_parser;

	vector<SystemCore> core_parser;
	createCoreVectorFromCoreMask(core_mask_parser, core_parser);
	vector<SystemCore> core_analyzer;
	createCoreVectorFromCoreMask(core_mask_analyzer, core_analyzer);

	assert((core_mask_analyzer & core_mask_parser) == 0);
	assert(core_mask_analyzer | core_mask_parser == core_without_master);
	assert(core_mask_analyzer | core_mask_parser | 
			DpdkDeviceList::getInstance().getDpdkMasterCore().Mask == core_mask_to_use);

	assign_queue_t nic_queue_assign = assign_queue_to_parser(device_list, core_parser);

	// create worker parser thread for each core
	vector<shared_ptr<ParserWorkerThread> > parser_thread_vec;
	vector<shared_ptr<AnalyzerWorkerThread> > analyzer_thread_vec;

	if (!create_worker_threads(nic_queue_assign, parser_thread_vec, analyzer_thread_vec)) {
		FATAL_ERROR("Thread allocation failed.");
	}

	// start all worker threads, mamory safe
#ifdef SPLIT_START_SUPPORT_PCPP
	vector<DpdkWorkerThread *> _thread_vec_all;
	transform(parser_thread_vec.cbegin(), parser_thread_vec.cend(), back_inserter(_thread_vec_all),
			[] (decltype(parser_thread_vec)::value_type _p) -> DpdkWorkerThread * {return _p.get(); });

	assert(core_parser.size() == _thread_vec_all.size());
	if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(core_mask_parser, _thread_vec_all)) {
		FATAL_ERROR("Couldn't start parser worker threads");
	}

	_thread_vec_all.clear();
	transform(analyzer_thread_vec.cbegin(), analyzer_thread_vec.cend(), back_inserter(_thread_vec_all),
			[] (decltype(analyzer_thread_vec)::value_type _p) -> DpdkWorkerThread * {return _p.get(); });

	assert(core_analyzer.size() == _thread_vec_all.size());
	if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(core_mask_analyzer, _thread_vec_all)) {
		FATAL_ERROR("Couldn't start analyzer worker threads");
	}
#else
	// #define START_PARSER_ONLY
	#ifdef START_PARSER_ONLY

		vector<DpdkWorkerThread *> _thread_vec_all;
		transform(parser_thread_vec.cbegin(), parser_thread_vec.cend(), back_inserter(_thread_vec_all),
				[] (decltype(parser_thread_vec)::value_type _p) -> DpdkWorkerThread * {return _p.get(); });

		assert(core_parser.size() == _thread_vec_all.size());
		if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(core_mask_parser, _thread_vec_all)) {
			FATAL_ERROR("Couldn't start parser worker threads");
		}
	
	#else

		vector<DpdkWorkerThread *> _thread_vec_all;
		transform(parser_thread_vec.cbegin(), parser_thread_vec.cend(), back_inserter(_thread_vec_all),
				[] (decltype(parser_thread_vec)::value_type _p) -> DpdkWorkerThread * {return _p.get(); });
		transform(analyzer_thread_vec.cbegin(), analyzer_thread_vec.cend(), back_inserter(_thread_vec_all),
			[] (decltype(analyzer_thread_vec)::value_type _p) -> DpdkWorkerThread * {return _p.get(); });

		assert(core_parser.size() + core_analyzer.size() == _thread_vec_all.size());
		if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(core_without_master, _thread_vec_all)) {
			FATAL_ERROR("Couldn't start parser worker threads");
		}

	#endif

#endif

	// register the on app close event to print summary stats on app termination
	ThreadStateManagement args(parser_thread_vec, analyzer_thread_vec);
	ApplicationEventHandler::getInstance().onApplicationInterrupted(interrupt_callback, &args);

	while (!args.stop) {
		multiPlatformSleep(5);
	}
}


auto DeviceConfig::configure_via_json(const json & jin) -> bool {
	
	if (p_configure_param) {
		LOGF("Device init param modification.");
		p_configure_param = NULL;
	}

	try {
		const auto _device_param = make_shared<DeviceConfigParam>();
		if (_device_param == nullptr) {
			WARN("device paramerter bad allocation");
			throw bad_alloc();
		}

		if (jin.find("DPDK") == jin.end()) {
			LOG_DEBUG("DPDK config enrty not found.");
			return false;
		}
		if (jin.find("Analyzer") != jin.end()) {
			j_cfg_analyzer = jin["Analyzer"];
		} else {
			WARN("Analyzer configuration not found, use default.");
		}
		if (jin.find("Learner") != jin.end()) {
			j_cfg_kmeans = jin["Learner"];
		} else {
			WARN("Learner configuration not found, use default.");
		}
		if (jin.find("Parser") != jin.end()) {
			j_cfg_parser = jin["Parser"];
		} else {
			WARN("Parser configuration not found, use default.");
		}

		const auto & dpdk_config = jin["DPDK"];
		if (dpdk_config.count("number_rx_queue")) {
			_device_param->number_rx_queue = 
				static_cast<nic_queue_id_t>(dpdk_config["number_rx_queue"]);
		}		
		if (dpdk_config.count("number_tx_queue")) {
			_device_param->number_tx_queue = 
				static_cast<nic_queue_id_t>(dpdk_config["number_tx_queue"]);
		}

		if (dpdk_config.count("core_use_for_analyze")) {
			_device_param->core_use_for_analyze = 
				static_cast<cpu_core_id_t>(dpdk_config["core_use_for_analyze"]);
		}
		if (dpdk_config.count("core_use_for_parser")) {
			_device_param->core_use_for_parser = 
				static_cast<cpu_core_id_t>(dpdk_config["core_use_for_parser"]);
		}
		if (dpdk_config.count("core_num")) {
			_device_param->core_num = 
				static_cast<cpu_core_id_t>(dpdk_config["core_num"]);
		}

		if (dpdk_config.count("verbose")) {
			verbose = dpdk_config["verbose"];
		}

		if (dpdk_config.count("dpdk_port_vec")) {
			const auto & _port_array = dpdk_config["dpdk_port_vec"];
			_device_param->dpdk_port_vec.clear();
			_device_param->dpdk_port_vec.assign(_port_array.cbegin(), _port_array.cend());
		}
		_device_param->dpdk_port_vec.shrink_to_fit();
		p_configure_param = _device_param;

	} catch(exception & e) {
		FATAL_ERROR(e.what());
	}

	return true;
}
