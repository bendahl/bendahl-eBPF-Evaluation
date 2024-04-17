/*
    This program traces TCP connections and some of their metrics.
    It is heavily inspired by the 'tcplife' program, created by Brendan Gregg and the BCC authors
    See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
    See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
*/
#include "comtrace.h"

// This is the main entrypoint to the application
int main(int argc, char *argv[]) {
    // beging program options
    // set help text to be shown when -h is given as an option
    CLI::App app{"Trace tcp connections using BPF"};

    uint duration = 30;
    std::string outFileName = "tcp_trace.log";
    bool writeCaptions = true;

    app.add_option("-d", duration, "duration for which tcp event should be recorded - e.g. 30s or 1m");
    app.add_option("-o", outFileName, "output file to write the recorded events to");
    app.add_flag("!-c", writeCaptions, "print captions");

    CLI11_PARSE(app, argc, argv);
    // end program options

    // Load BPF program
    auto skel = comtrace_bpf__open_and_load();
    if (!skel) {
        std::cerr << "failed to open BPF skeleton" << std::endl;
        return 1;
    }
    auto tracelink = bpf_program__attach_tracepoint(skel->progs.inet_sock_set_state, "sock", "inet_sock_set_state");
    if (!tracelink) {
        std::cout << "failed to attach trace program" << std::endl;
        return 1;
    }

    // initialize connection cache
    auto connections = std::map<connection, connectionMeta>();
    auto rb = ring_buffer__new(bpf_map__fd(skel->maps.ip_events), handleEvent, &connections, nullptr);
    if (!rb) {
        std::cout << "failed to create ringbuffer" << std::endl;
        return 1;
    }

    std::cout << "Tracing tcp connections for " << duration << " seconds. Stand by..." << std::endl;

    // measure time in order to determine when to stop tracing
    auto begin = std::chrono::steady_clock::now();
    auto end = std::chrono::steady_clock::now();
    auto secondsElapsed = std::chrono::duration_cast<std::chrono::seconds>( end - begin);

    // poll ring buffer until time limit has been reached or a termination signal has been received
    int err = 0;
    while (secondsElapsed.count() < duration) {
        // see https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c for reference
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            std::cout << "error pulling ringbufffer: " << err << std::endl;
            break;
        }
        end = std::chrono::steady_clock::now();
        secondsElapsed = std::chrono::duration_cast<std::chrono::seconds>( end - begin);
    }

    // write output file
    std::ofstream outFile;
    outFile.open(outFileName);
    if (writeCaptions) {
        outFile << std::setw(10) << "PID"
                << std::setw(20) << "COMM"
                << std::setw(40) << "LOCAL_IP"
                << std::setw(14) << "LOCAL_PORT"
                << std::setw(40) << "REMOTE_IP"
                << std::setw(14) << "REMOTE_PORT"
                << std::setw(10) << "RX_BYTES"
                << std::setw(10) << "TX_BYTES"
                << std::setw(10) << "MS"
                << std::endl;
    }

    for (const auto& con : connections) {
        // ignore pid 0
        if (con.second.pid == 0) {
            continue;
        }
        auto delta = con.second.endTs - con.second.startTs;
        if (delta > 0) {
            delta = delta / 1000000;
        } else {
            delta = 0;
        }

        outFile << std::setw(10) << con.second.pid
                << std::setw(20) << con.second.comm
                << std::setw(40) << con.first.saddr
                << std::setw(14) << con.first.sport
                << std::setw(40) << con.first.daddr
                << std::setw(14) << con.first.dport
                << std::setw(10) << con.second.bytesReceived
                << std::setw(10) << con.second.bytesSent
                << std::setw(10) << delta
                << std::endl;
    }
    outFile.close();

    std::cout << "Done tracing. Results have been written to " << outFileName << std::endl;
    return err;
}