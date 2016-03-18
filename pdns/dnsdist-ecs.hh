#pragma once

extern size_t g_EdnsUDPPayloadSize;
int rewriteResponseWithoutEDNS(const char * packet, size_t len, vector<uint8_t>& newContent);
int locateEDNSOptRR(const char * packet, size_t len, const char ** optStart, size_t * optLen, bool * last);
void handleEDNSClientSubnet(char * packet, size_t packetSize, unsigned int consumed, uint16_t * len, string& largerPacket, bool * ednsAdded, const ComboAddress& remote);
void generateOptRR(const std::string& optRData, string& res);
