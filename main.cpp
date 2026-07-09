#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <memory>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <condition_variable>

struct ParsedPacket {
    std::string srcIp;
    std::string dstIp;
    std::string protocol;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t length = 0;
    std::string ipVersion;
};

class OptimizedRingBuffer {
private:
    std::vector<ParsedPacket> buffer_;
    size_t capacity_;
    std::atomic<size_t> head_{0};
    std::atomic<size_t> tail_{0};
    std::mutex signalMutex_;
    std::condition_variable signalCv_;

public:
    OptimizedRingBuffer(size_t capacity) : capacity_(capacity) {
        buffer_.resize(capacity);
    }

    void push(const ParsedPacket& packet) {
        size_t currentTail = tail_.load(std::memory_order_relaxed);
        buffer_[currentTail] = packet; 
        
        tail_.store((currentTail + 1) % capacity_, std::memory_order_release);
        signalCv_.notify_one(); 
    }

    bool pop(ParsedPacket& packet, const std::atomic<bool>& keepRunning) {
        size_t currentHead = head_.load(std::memory_order_relaxed);
        
        while (currentHead == tail_.load(std::memory_order_acquire)) {
            if (!keepRunning) return false;
            
            std::unique_lock<std::mutex> lock(signalMutex_);
            signalCv_.wait_for(lock, std::chrono::milliseconds(100), [this, currentHead]() {
                return currentHead != tail_.load(std::memory_order_acquire);
            });
            currentHead = head_.load(std::memory_order_relaxed);
            if (currentHead == tail_.load(std::memory_order_acquire) && !keepRunning) return false;
        }

        packet = buffer_[currentHead];
        head_.store((currentHead + 1) % capacity_, std::memory_order_release);
        return true;
    }
};

OptimizedRingBuffer g_packetRingBuffer(8192);
std::atomic<bool> g_keepRunning{true};

void packetProcessingWorker() {
    ParsedPacket pkt;
    while (g_packetRingBuffer.pop(pkt, g_keepRunning)) {
        std::cout << "[METRIC] [" << pkt.ipVersion << "] [" << pkt.protocol << "] "
                  << pkt.srcIp << ":" << pkt.srcPort << " -> "
                  << pkt.dstIp << ":" << pkt.dstPort 
                  << " | Payload: " << pkt.length << " bytes\n";
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *ethHeader = (struct ether_header *) packet;
    uint16_t ethernetType = ntohs(ethHeader->ether_type);
    
    ParsedPacket parsedPkt;
    parsedPkt.length = pkthdr->len;
    const u_char *layer4Ptr = nullptr;
    uint8_t nextProtocol = 0;

    if (ethernetType == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        char srcStr[INET_ADDRSTRLEN];
        char dstStr[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstStr, INET_ADDRSTRLEN);
        
        parsedPkt.srcIp = srcStr;
        parsedPkt.dstIp = dstStr;
        parsedPkt.ipVersion = "IPv4";
        nextProtocol = ipHeader->ip_p;
        
        int ipHeaderLength = ipHeader->ip_hl * 4;
        layer4Ptr = packet + sizeof(struct ether_header) + ipHeaderLength;
    } 
    else if (ethernetType == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6Header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char srcStr[INET6_ADDRSTRLEN];
        char dstStr[INET6_ADDRSTRLEN];
        
        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcStr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstStr, INET6_ADDRSTRLEN);
        
        parsedPkt.srcIp = srcStr;
        parsedPkt.dstIp = dstStr;
        parsedPkt.ipVersion = "IPv6";
        nextProtocol = ip6Header->ip6_nxt;
        layer4Ptr = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
    } 
    else {
        return; 
    }

    if (nextProtocol == IPPROTO_TCP && layer4Ptr) {
        struct tcphdr *tcpHeader = (struct tcphdr *) layer4Ptr;
        parsedPkt.protocol = "TCP";
        parsedPkt.srcPort = ntohs(tcpHeader->th_sport);
        parsedPkt.dstPort = ntohs(tcpHeader->th_dport);
    } 
    else if (nextProtocol == IPPROTO_UDP && layer4Ptr) {
        struct udphdr *udpHeader = (struct udphdr *) layer4Ptr;
        parsedPkt.protocol = "UDP";
        parsedPkt.srcPort = ntohs(udpHeader->uh_sport);
        parsedPkt.dstPort = ntohs(udpHeader->uh_dport);
    } else {
        parsedPkt.protocol = "OTHER";
    }

    g_packetRingBuffer.push(parsedPkt);
}

int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    if (pcap_findalldevs(&alldevs, errorBuffer) == -1 || alldevs == nullptr) {
        std::cerr << "Error finding network devices: " << errorBuffer << std::endl;
        return 1;
    }
    
    std::string deviceName = alldevs->name;
    pcap_freealldevs(alldevs);

    std::cout << "[SYSTEM] Initializing capturing interface on: " << deviceName << "...\n";
    
    pcap_t* rawHandle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);
    if (rawHandle == nullptr) {
        std::cerr << "Could not open device: " << errorBuffer << std::endl;
        return 1;
    }
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(rawHandle, pcap_close);

    struct bpf_program filterProgram;
    std::string filterExpression = "tcp or udp"; 
    
    if (pcap_compile(handle.get(), &filterProgram, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "BPF Compilation failed: " << pcap_geterr(handle.get()) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle.get(), &filterProgram) == -1) {
        std::cerr << "BPF Filter Injection failed: " << pcap_geterr(handle.get()) << std::endl;
        return 1;
    }
    std::cout << "[KERNEL] BPF Filter successfully injected: [" << filterExpression << "]\n";

    std::thread worker(packetProcessingWorker);
    std::cout << "[SYSTEM] Dual-Stack Network Parsing Engine Online.\n";

    pcap_loop(handle.get(), 50, packetHandler, nullptr);

    std::cout << "\n[SYSTEM] Terminating loop. Flushing ring buffer...\n";
    g_keepRunning = false;
    if (worker.joinable()) {
        worker.join();
    }
    
    pcap_freecode(&filterProgram);
    return 0;
}
