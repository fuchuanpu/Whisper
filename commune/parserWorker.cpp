#include "parserWorker.hpp"


using namespace Whisper;


bool ParserWorkerThread::run(uint32_t core_id) 
{

	if (p_parser_config == nullptr) {
		FATAL_ERROR("NULL parser configuration parameters.");
	}

	// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
	if (p_dpdk_config->nic_queue_list.size() == 0) {
		WARN("NO NIC queue bind for parser on core %2d.", core_id);
		return false;
	}

	meta_pkt_arr = shared_ptr<PacketMetaData[]>(new PacketMetaData[p_parser_config->meta_pkt_arr_size](), 
													std::default_delete<PacketMetaData[]>());

	if (meta_pkt_arr == nullptr) {
		FATAL_ERROR("Meta data array: bad allocation.");
	}

	// the size of receive burst, must be smaller than 2 << 16
	using p_mbuf_t = MBufRawPacket*;
	p_mbuf_t * packet_arr = new p_mbuf_t[p_parser_config->max_receive_burts];
	if (packet_arr == nullptr) {
		WARN("Packet receving buffer allocation error.");
		return false;
	}
	// LOGF("Parser on core # %2d start.", core_id);

	if (p_parser_config->verbose_mode & ParserConfigParam::verbose_type::INIT) {
		LOGF("Parser on core # %2d start.", core_id);
	}
	m_stop = false;

    thread verbose_stat(&ParserWorkerThread::verbose_tracing_thread, this);
    verbose_stat.detach();

	const auto _f_get_meta_pkt_info = [packet_arr, this] 
						(const size_t i, const DpdkDevice* dev) -> shared_ptr<PacketMetaData> {
		pcpp::Packet parsedPacket(packet_arr[i]);

		// ignore the packets out of the scope of TCP/IPv4 protocol stack
		if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
			pcpp::IPv4Layer * IPlay = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

			uint32_t addr = IPlay->getSrcIPv4Address().toInt();
			uint16_t length = ntohs(IPlay->getIPv4Header()->totalLength);
			double_t ts = GET_DOUBLE_TS(packet_arr[i]->getPacketTimeStamp());

			++ parsed_pkt_num[dev->getDeviceId()];
			parsed_pkt_len[dev->getDeviceId()] += length;
			
			uint16_t type_code = type_identify_mp::TYPE_UNKNOWN;
			if (parsedPacket.isPacketOfType(pcpp::TCP)) {
				pcpp::TcpLayer* tcp_layer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
				if (tcp_layer->getTcpHeader()->synFlag) {
					type_code = type_identify_mp::TYPE_TCP_SYN;
				} else if (tcp_layer->getTcpHeader()->finFlag) {
					type_code = type_identify_mp::TYPE_TCP_FIN;
				} else if (tcp_layer->getTcpHeader()->rstFlag) {
					type_code = type_identify_mp::TYPE_TCP_RST;
				} else {
					type_code = type_identify_mp::TYPE_TCP;
				}
			} else if (IPlay->getNextLayer()->getProtocol() == pcpp::UDP) {
				type_code = type_identify_mp::TYPE_UDP;
			} else {
				type_code = type_identify_mp::TYPE_UNKNOWN;
			}
			
			return make_shared<PacketMetaData>(addr, type_code, length, ts);
			
		} else {
			return nullptr;
		}
	};

	parser_start_time = get_time_spec();

	// main loop, runs until be told to stop
	while (!m_stop) {
		// go over all DPDK devices configured for this worker/core
		for (parser_queue_assign_t::iterator iter = p_dpdk_config->nic_queue_list.begin(); 
			 								 iter != p_dpdk_config->nic_queue_list.end(); 
											 iter++) {
			// for each DPDK device go over all RX queues configured for this worker/core
			for (vector<nic_queue_id_t>::iterator iter2 = iter->second.begin(); 
									   iter2 != iter->second.end(); 
									   iter2++) {
				DpdkDevice* dev = iter->first;

				// receive packets from network on the specified DPDK device and RX queue
				uint16_t packetsReceived = dev->receivePackets(packet_arr, p_parser_config->max_receive_burts, *iter2);
				
				// iterate all of the packets and parse the metadata
				for (uint16_t i = 0; i < packetsReceived; i++) {

					const auto p_meta = _f_get_meta_pkt_info(i, dev);
					if (p_meta == nullptr) {
						continue;
					}

					assert(meta_index <= p_parser_config->meta_pkt_arr_size);
					acquire_semaphore();
					meta_pkt_arr[meta_index] = *p_meta;
					meta_index ++;
					release_semaphore();

					// the array of parsed queue reach its max
					if (meta_index == p_parser_config->meta_pkt_arr_size) {
						WARNF("Parser on core # %2d: parse queue reach max.", (int) this->getCoreId());
						// clear the meta data buffer, just for testing
											acquire_semaphore();
						acquire_semaphore();
						meta_index = 0;
						release_semaphore();
					}

				}
			}
		}
	}

	for (size_t i = 0; i < p_parser_config->max_receive_burts; i ++) {
		if (packet_arr[i] != nullptr) {
			delete packet_arr[i];
		}
	}
	delete packet_arr;

	return true;
}


void ParserWorkerThread::verbose_tracing_thread() const
{
	while (! m_stop) {
		if (p_parser_config->verbose_mode & ParserConfigParam::verbose_type::TRACING) {
			stringstream ss;
			ss << "Parser on core # " << setw(2) << m_core_id << ": ";
			size_t index = 0;
			for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
				ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
					
						ss << "DPDK Port" << setw(2) << ite->first->getDeviceId();
						ss << " [" << setw(5) << setprecision(3) 
								<< ((double) parsed_pkt_num[index] / 1e6) / p_parser_config->verbose_interval << " Mpps / ";

						ss << setw(5) << setprecision(3) 
								<< ((double) parsed_pkt_len[index] / (1e9 / 8)) / p_parser_config->verbose_interval << " Gbps]\t";
				
					
					sum_parsed_pkt_num[index] += parsed_pkt_num[index];
					sum_parsed_pkt_len[index] += parsed_pkt_len[index];
					
					parsed_pkt_num[index] = 0;
					parsed_pkt_len[index] = 0;
					index ++;
			}
			ss << endl;
			printf("%s", ss.str().c_str());

		} else {
			size_t index = 0;
			for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
				ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
					sum_parsed_pkt_num[index] += parsed_pkt_num[index];
					sum_parsed_pkt_len[index] += parsed_pkt_len[index];
					
					parsed_pkt_num[index] = 0;
					parsed_pkt_len[index] = 0;
					index ++;
			}
		}
		sleep(p_parser_config->verbose_interval);
	}
}


void ParserWorkerThread::verbose_final() const
{
	if (p_parser_config->verbose_mode & ParserConfigParam::verbose_type::SUMMARY) {
		stringstream ss;
		ss << "[Performance Statistic] Parser on core # " << setw(2) << m_core_id << ": ";
		ss << " Runtime: " << setw(5) << setprecision(3) << (parser_end_time - parser_start_time) << "s\n";
		size_t index = 0;
		for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
			ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
				double_t _device_overall_packet_speed = 
						((double) sum_parsed_pkt_num[index] / 1e6) / (parser_end_time - parser_start_time);

				double_t _device_overall_byte_speed = 
						((double) sum_parsed_pkt_len[index] / (1e9 / 8)) / (parser_end_time - parser_start_time);

				ss << "DPDK Port" << setw(2) << ite->first->getDeviceId();
				ss << " [" << setw(5) << setprecision(3) << _device_overall_packet_speed << " Mpps / ";
				ss << setw(5) << setprecision(3) << _device_overall_byte_speed << " Gbps]\t";
				
				index ++;

		}
		ss << endl;
		printf("%s", ss.str().c_str());
	} else {
		size_t index = 0;
		for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
			ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
				double_t _device_overall_packet_speed = 
						((double) sum_parsed_pkt_num[index] / 1e6) / (parser_end_time - parser_start_time);

				double_t _device_overall_byte_speed = 
						((double) sum_parsed_pkt_len[index] / (1e9 / 8)) / (parser_end_time - parser_start_time);

				index ++;
		}
	}
}


auto ParserWorkerThread::get_overall_performance() const -> pair<double_t, double_t> 
{
	if (!m_stop) {
		WARN("Parsing not finsih, DO NOT collect result.");
		return {0, 0};
	}
	size_t index = 0;
	double_t thread_overall_num = 0, thread_overall_len = 0;
	for (parser_queue_assign_t::const_iterator ite = cbegin(p_dpdk_config->nic_queue_list); 
		ite != cend(p_dpdk_config->nic_queue_list); ite ++) {
			double_t _device_overall_packet_speed = 
					((double) sum_parsed_pkt_num[index] / 1e6) / (parser_end_time - parser_start_time);

			double_t _device_overall_byte_speed = 
					((double) sum_parsed_pkt_len[index] / (1e9 / 8)) / (parser_end_time - parser_start_time);

			thread_overall_num += _device_overall_packet_speed;
			thread_overall_len += _device_overall_byte_speed;
			index ++;
		}
	return {thread_overall_num, thread_overall_len};
}


auto ParserWorkerThread::configure_via_json(const json & jin) -> bool  
{
	if (p_parser_config != nullptr) {
		WARN("Analyzer configuration overlap.");
		return false;
	}

	p_parser_config = make_shared<ParserConfigParam>();
	if (p_parser_config == nullptr) {
		WARNF("Parser configuration paramerter bad allocation.");
		return false;
	}

	try {
		if (jin.count("max_receive_burts")) {
			p_parser_config->max_receive_burts = 
				static_cast<decltype(p_parser_config->max_receive_burts)>(jin["max_receive_burts"]);
			if (p_parser_config->max_receive_burts > RECEIVE_BURST_LIM) {
				FATAL_ERROR("Max receive burst exceed the length of maximum buffer size.");
			}
		}
		if (jin.count("meta_pkt_arr_size")) {
			p_parser_config->meta_pkt_arr_size = 
				static_cast<decltype(p_parser_config->meta_pkt_arr_size)>(jin["meta_pkt_arr_size"]);
			if (p_parser_config->meta_pkt_arr_size > META_PKT_ARR_LIN) {
				FATAL_ERROR("Packet meta data buffer exceed.");
			}
		}

		if (jin.count("verbose_mode")) {
			json _j_mode = jin["verbose_mode"];
			if (verbose_mode_map.count(_j_mode) != 0) {
				p_parser_config->verbose_mode |= verbose_mode_map.at(_j_mode);
			} else {
				WARNF("Unknown verbose mode: %s", static_cast<string>(_j_mode).c_str());
				throw logic_error("Parse error Json tag: verbose_mode\n");
			}
		}
		if (jin.count("verbose_interval")) {
			p_parser_config->verbose_interval = 
				static_cast<decltype(p_parser_config->verbose_interval)>(jin["verbose_interval"]);
		}
	} catch (exception & e) {
		WARN(e.what());
		return false;
	}
	return true;
}