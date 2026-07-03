// export_states — run a pcap through the engine's reassembler + behavioral
// encoder and dump per-4-tuple state strings. This is the "translator" step
// of the train-on-pcap pipeline: the models are then trained on the SAME
// encoder output the live engine produces, so there is no train/runtime drift.
//
// Handles truncated captures (CTU-13 *.truncated.pcap): byte counts come from
// the IP header length, so flow stats stay accurate even with cut payloads.
//
// Usage: export_states <capture.pcap> <out_states.csv>
// Output CSV: src,dst,dport,state

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#endif

#include "config.hpp"
#include "logger.hpp"
#include "packet_types.hpp"
#include "wirewolf_types.hpp"
#include "tcp_reassembly.hpp"
#include "thread_safe_queue.hpp"

#include <chrono>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cerr << "Usage: export_states <capture.pcap> <out_states.csv>\n";
    return 1;
  }
  Logger::instance().set_level(LogLevel::INFO);

  WirewolfConfig cfg;
  cfg.interface = argv[1]; // offline (.pcap)
  cfg.use_windivert = false;

  ThreadSafeQueue<FlowPtr> q(4096);
  q.set_blocking(false); // discard reassembled flows; we only want state strings

  TcpReassembler reasm(cfg, q);
  reasm.set_behavioral_export(true); // accumulate state strings, no scoring

  std::cout << "Exporting behavioral state strings from " << argv[1] << " ...\n";
  auto t0 = std::chrono::steady_clock::now();
  reasm.start(); // blocks until EOF + flush (offline)
  double secs =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
          .count();

  reasm.dump_behavioral_states(argv[2]);
  std::cout << "Done in " << secs << "s -> " << argv[2] << "\n";
  return 0;
}
