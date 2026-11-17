/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Yeatol <vim@vimer.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "network.h"

#include <span>
#include <array>
#include <vector>
#include <thread>
#include <stdint.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/cpuset.h>
#include <sys/socket.h>
#include <netinet/in.h>

static bool network_bind(int fd, int domain, uint16_t port)
{
    if (domain == AF_INET)
    {
        sockaddr_in address     = {};
        address.sin_family      = AF_INET;
        address.sin_port        = htons(port);
        address.sin_addr.s_addr = INADDR_ANY;
        return bind(fd, (sockaddr*)&address, sizeof(address)) != -1;
    }

    if (domain == AF_INET6)
    {
        int ipv6only  = 1;

        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(int)) == -1) return false;

        sockaddr_in6 address = {};
        address.sin6_family  = AF_INET6;
        address.sin6_port    = htons(port);
        address.sin6_addr    = in6addr_any;
        return bind(fd, (sockaddr*)&address, sizeof(address)) != -1;
    }

    return false;
}

static int network_udp_socket(int domain, uint16_t port)
{
    int fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);

    if (fd == -1) return -1;

    int reuseaddr = 1;
    int reuseport = 1;

    if (setsockopt(fd, SOL_SOCKET,   SO_REUSEADDR,    &reuseaddr, sizeof(int)) == -1) { close(fd); return -1; }
    if (setsockopt(fd, SOL_SOCKET,   SO_REUSEPORT_LB, &reuseport, sizeof(int)) == -1) { close(fd); return -1; }

    if (!network_bind(fd, domain, port)) { close(fd); return -1; }

    return fd;
}

static void network_udp_event_handler(const struct kevent& e, int udp_ipv4, int udp_ipv6)
{
    static constexpr uint8_t ipv4_mapped[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF};

    static thread_local std::array<uint8_t, 1232> buffer;

    while(true)
    {
        sockaddr_storage address = {};

        socklen_t address_size = sizeof(address);

        int size = recvfrom(e.ident, buffer.data(), buffer.size(), 0, (sockaddr*)&address, &address_size);

        if (size < 0) break;

        uint8_t  ip[16];
        uint16_t port = 0;

        if (address.ss_family == AF_INET)
        {
            sockaddr_in* addr_in = (sockaddr_in*)&address;
            memcpy(ip, ipv4_mapped, 12);
            memcpy(ip + 12, &addr_in->sin_addr, 4);
            port = addr_in->sin_port;
        }
        else
        {
            sockaddr_in6* addr_in6 = (sockaddr_in6*)&address;
            memcpy(ip, &addr_in6->sin6_addr, 16);
            port = addr_in6->sin6_port;
        }

        bool drop = true;

        network_udp_handler(std::span<uint8_t, 16>(ip, 16), port, std::span<uint8_t, 1232>(buffer.data(), buffer.size()), (uint32_t&)size, drop);

        if (drop) continue;

        int udp_socket = -1;

        sockaddr_storage peer_address = {};

        socklen_t peer_address_size = 0;

        if (std::memcmp(ip, ipv4_mapped, sizeof(ipv4_mapped)) == 0)
        {
            sockaddr_in* addr_in = (sockaddr_in*)&peer_address;
            addr_in->sin_family = AF_INET;
            memcpy(&addr_in->sin_addr, ip + 12, 4);
            addr_in->sin_port = port;
            peer_address_size = sizeof(sockaddr_in);
            udp_socket = udp_ipv4;
        }
        else
        {
            sockaddr_in6* addr_in6 = (sockaddr_in6*)&peer_address;
            addr_in6->sin6_family = AF_INET6;
            memcpy(&addr_in6->sin6_addr, ip, 16);
            addr_in6->sin6_port = port;
            peer_address_size = sizeof(sockaddr_in6);
            udp_socket = udp_ipv6;
        }

        sendto(udp_socket, buffer.data(), size, 0, (sockaddr*)&peer_address, peer_address_size);
    }
}

static bool network_kqueue_add_read(int kqueue_id, int fd)
{
    struct kevent event = {};
    EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    return kevent(kqueue_id, &event, 1, 0, 0, 0) != -1;
}

static void network_thread(int cpu_id, uint16_t port)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(mask), &mask) != 0) _exit(-1);

    int kqueue_id = kqueue1(O_CLOEXEC);
    int udp_ipv4  = network_udp_socket(AF_INET,  port);
    int udp_ipv6  = network_udp_socket(AF_INET6, port);

    if (!network_kqueue_add_read(kqueue_id, udp_ipv4)) _exit(-1);
    if (!network_kqueue_add_read(kqueue_id, udp_ipv6)) _exit(-1);

    std::vector<struct kevent> events(1024);

    while (true)
    {
        int size = kevent(kqueue_id, 0, 0, events.data(), events.size(), 0);
        for (int i = 0; i < size; ++i)
        {
            network_udp_event_handler(events[i], udp_ipv4, udp_ipv6);
        }
    }
}

void network_server(uint16_t port)
{
    size_t cpu_count = std::thread::hardware_concurrency();
    for (int cpu_id = 0; cpu_id < cpu_count; ++cpu_id)
    {
        std::thread(network_thread, cpu_id, port).detach();
    }
}

__attribute__((weak)) void network_udp_handler(std::span<uint8_t, 16> ip, uint16_t& port, std::span<uint8_t, 1232> buffer, uint32_t& size, bool& drop)
{
}
