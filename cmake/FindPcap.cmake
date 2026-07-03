find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap wpcap)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Pcap DEFAULT_MSG PCAP_LIBRARY PCAP_INCLUDE_DIR)
mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
if(Pcap_FOUND AND NOT TARGET pcap::pcap)
    add_library(pcap::pcap UNKNOWN IMPORTED)
    set_target_properties(pcap::pcap PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
endif()
