// Synthetic libcurl / libproxy / libiconv boundary for the ownership harness.
// No real libcurl is linked: no socket, DNS lookup or transfer can happen.

#ifndef CURL_OWNERSHIP_STUBS_H
#define CURL_OWNERSHIP_STUBS_H

#include <string>
#include <vector>

struct HarnessScenario {
    int ticks = 0;              // curl_multi_perform calls that still report a running transfer
    int tickMs = 0;             // sleep per tick, so the plugin's 100 ms callback throttle fires
    std::string body;           // delivered to CURLOPT_WRITEFUNCTION
    std::string header;         // delivered to CURLOPT_HEADERFUNCTION
    bool certinfo = false;      // CURLINFO_CERTINFO reports 2 certificates x 2 lines
    int result = 0;             // CURLcode of the finished transfer
};

void harness_set_scenario(const HarnessScenario &s);
int harness_easy_performs();
int harness_multi_transfers();
int harness_live_easy_handles();
int harness_live_slists();
std::vector<std::string> harness_slist_option(int option);  // copied at curl_easy_setopt time
long harness_long_option(int option, long fallback);
std::string harness_string_option(int option);
void harness_probe_denied_iconv();
void harness_probe_denied_proxy();

#endif
