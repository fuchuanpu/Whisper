# CMake basics
# Note that the Pytorch 1.6 must use C++ 14
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(commune)
set(CMAKE_CXX_STANDARD 14)

# Add library src
aux_source_directory(. DIR_LIB_SRCS)
add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

# 4. Link pytorch lib 
target_link_libraries(${PROJECT_NAME} "${TORCH_LIBRARIES}")

# 3. Link Pcapplusplus static dependencies
target_link_libraries(${PROJECT_NAME} 
        libPcap++.a
        libPacket++.a
        libCommon++.a
)

# 2. Link DPDK libraries
target_link_libraries(${PROJECT_NAME}
		rte_acl
		rte_bbdev
		rte_bitratestats
		rte_bpf
		rte_bus_dpaa
		rte_bus_fslmc
		rte_bus_ifpga
		rte_bus_pci
		rte_bus_vdev
		rte_bus_vmbus
		rte_cfgfile
		rte_cmdline
		rte_common_cpt
		rte_common_dpaax
		rte_common_octeontx
		rte_common_octeontx2
		rte_compressdev
		rte_cryptodev
		rte_distributor
		rte_eal
		rte_efd
		rte_ethdev
		rte_eventdev
		rte_fib
		rte_flow_classify
		rte_gro
		rte_gso
		rte_hash
		rte_ip_frag
		rte_ipsec
		rte_jobstats
		rte_kni
		rte_kvargs
		rte_latencystats
		rte_lpm
		rte_mbuf
		rte_member
		rte_mempool
		rte_mempool_bucket
		rte_mempool_dpaa
		rte_mempool_dpaa2
		rte_mempool_octeontx
		rte_mempool_octeontx2
		rte_mempool_ring
		rte_mempool_stack
		rte_meter
		rte_metrics
		rte_net
		rte_pci
		rte_pdump
		rte_pipeline
		rte_pmd_af_packet
		rte_pmd_ark
		rte_pmd_atlantic
		rte_pmd_avp
		rte_pmd_axgbe
		rte_pmd_bbdev_fpga_lte_fec
		rte_pmd_bbdev_null
		rte_pmd_bbdev_turbo_sw
		rte_pmd_bnxt
		rte_pmd_bond
		rte_pmd_caam_jr
		rte_pmd_crypto_scheduler
		rte_pmd_cxgbe
		rte_pmd_dpaa
		rte_pmd_dpaa2
		rte_pmd_dpaa2_event
		rte_pmd_dpaa2_sec
		rte_pmd_dpaa_event
		rte_pmd_dpaa_sec
		rte_pmd_dsw_event
		rte_pmd_e1000
		rte_pmd_ena
		rte_pmd_enetc
		rte_pmd_enic
		rte_pmd_failsafe
		rte_pmd_fm10k
		rte_pmd_hinic
		rte_pmd_hns3
		rte_pmd_i40e
		rte_pmd_iavf
		rte_pmd_ice
		rte_pmd_ifc
		rte_pmd_ixgbe
		rte_pmd_kni
		rte_pmd_liquidio
		rte_pmd_memif
		rte_pmd_netvsc
		rte_pmd_nfp
		rte_pmd_nitrox
		rte_pmd_null
		rte_pmd_null_crypto
		rte_pmd_octeontx
		rte_pmd_octeontx2
		rte_pmd_octeontx2_crypto
		rte_pmd_octeontx2_event
		rte_pmd_octeontx_compress
		rte_pmd_octeontx_crypto
		rte_pmd_octeontx_event
		rte_pmd_opdl_event
		rte_pmd_pcap
		rte_pmd_pfe
		rte_pmd_qat
		rte_pmd_qede
		rte_pmd_ring
		rte_pmd_sfc
		rte_pmd_skeleton_event
		rte_pmd_softnic
		rte_pmd_sw_event
		rte_pmd_tap
		rte_pmd_thunderx
		rte_pmd_vdev_netvsc
		rte_pmd_vhost
		rte_pmd_virtio
		rte_pmd_virtio_crypto
		rte_pmd_vmxnet3
		rte_port
		rte_power
		rte_rawdev
		rte_rawdev_dpaa2_cmdif
		rte_rawdev_dpaa2_qdma
		rte_rawdev_ioat
		rte_rawdev_ntb
		rte_rawdev_octeontx2_dma
		rte_rawdev_skeleton
		rte_rcu
		rte_reorder
		rte_rib
		rte_ring
		rte_sched
		rte_security
		rte_stack
		rte_table
		rte_timer
		rte_vhost
		-Wl,--no-whole-archive
)

# 1. Link Basic System Libraries
target_link_libraries(${PROJECT_NAME} 
        pthread
        rt
        dl
        m
        numa
        pcap
)

# 0. Link Basic System Libraries
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(${PROJECT_NAME} OpenMP::OpenMP_CXX)
endif()

target_link_libraries(${PROJECT_NAME}
    armadillo
    mlpack
)