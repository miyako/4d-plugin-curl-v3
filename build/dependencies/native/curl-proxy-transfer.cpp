// Reuse process-only settings without changing the archived proxy build recipes.
#define main unused_proxy_behavior_main
#include "../proxy/behavior.cpp"
#undef main
#include <cstdio>
#include <cstring>
#include <memory>
#include <curl/curl.h>
#include "probe-json.h"

int main(int argc, char **argv)
{
    try {
        require(argc == 7, "Expected mode, PAC URL, proxy port, target URL, response path and DNS fixture");
        const std::string mode(argv[1]);
        require(mode == "manual" || mode == "bypass" || mode == "pac", "invalid proxy fixture mode");
        const int port = std::stoi(argv[3]);
        require(port > 0 && port <= 65535, "invalid loopback proxy port");
        Configuration config;
        config.clear();
        if (mode == "pac") {
#ifdef _WIN32
            config.pac(argv[2]);
#else
            config.number("ProxyAutoConfigEnable", 1);
            config.text("ProxyAutoConfigURLString", argv[2]);
#endif
        } else {
#ifdef _WIN32
            config.number("ProxyEnable", 1);
            config.text("ProxyServer", "http=127.0.0.1:" + std::to_string(port));
            if (mode == "bypass")
                config.text("ProxyOverride", "bypass.invalid;<local>");
#else
            config.number("HTTPEnable", 1);
            config.number("HTTPPort", port);
            // Use mutable storage: the candidate backend requests a direct C-string pointer.
            CFMutableStringRef address = CFStringCreateMutable(NULL, 0);
            require(address != NULL, "synthetic proxy address allocation");
            CFStringAppendCString(address, "127.0.0.1", kCFStringEncodingUTF8);
            CFDictionarySetValue(settings, CFSTR("HTTPProxy"), address);
            CFRelease(address);
            if (mode == "bypass") {
                const void *bypass[] = {CFSTR("bypass.invalid"), CFSTR("nonmatch.invalid")};
                CFArrayRef exceptions = CFArrayCreate(NULL, bypass, 2, &kCFTypeArrayCallBacks);
                require(exceptions != NULL, "synthetic bypass list allocation");
                CFDictionarySetValue(settings, CFSTR("ExceptionsList"), exceptions);
                CFRelease(exceptions);
            }
#endif
        }
        require(curl_global_sslset(CURLSSLBACKEND_NONE, "openssl", NULL) == CURLSSLSET_OK,
                "OpenSSL backend selection");
        require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl global initialization");
        struct RuntimeCleanup { ~RuntimeCleanup() { curl_global_cleanup(); } } runtime;
        std::unique_ptr<pxProxyFactory, decltype(&px_proxy_factory_free)> factory(
            px_proxy_factory_new(), px_proxy_factory_free);
        require(factory.get() != NULL, "proxy factory allocation");
        std::unique_ptr<char *, decltype(&px_proxy_factory_free_proxies)> proxies(
            px_proxy_factory_get_proxies(factory.get(), argv[4]), px_proxy_factory_free_proxies);
        require(proxies.get() != NULL, "proxy resolution returned no list");
        std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolution(
            curl_slist_append(NULL, argv[6]), curl_slist_free_all);
        require(resolution.get() != NULL, "loopback DNS fixture allocation");
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> easy(curl_easy_init(), curl_easy_cleanup);
        require(easy.get() != NULL, "curl handle allocation");
        std::unique_ptr<FILE, decltype(&fclose)> response(fopen(argv[5], "wb"), fclose);
        require(response.get() != NULL, "response file creation");
#define SET(option, value) require(curl_easy_setopt(easy.get(), option, value) == CURLE_OK, #option)
        SET(CURLOPT_URL, argv[4]);
        SET(CURLOPT_PROTOCOLS_STR, "http");
        SET(CURLOPT_RESOLVE, resolution.get());
        SET(CURLOPT_PROXY, "");
        SET(CURLOPT_NOPROXY, "");
        SET(CURLOPT_CONNECTTIMEOUT, 5L);
        SET(CURLOPT_TIMEOUT, 15L);
        SET(CURLOPT_NOSIGNAL, 1L);
        SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
        SET(CURLOPT_WRITEDATA, response.get());
        for (unsigned int j = 0; proxies.get()[j]; ++j) {
            const char *proxy = proxies.get()[j];
            if (!strncmp("direct://", proxy, 9))
                continue;
            SET(CURLOPT_PROXY, proxy);
            if (!strncmp("https", proxy, 5))
                SET(CURLOPT_PROXYTYPE, (long)CURLPROXY_HTTPS);
            else if (!strncmp("http", proxy, 4))
                SET(CURLOPT_PROXYTYPE, (long)CURLPROXY_HTTP);
            else if (!strncmp("socks4", proxy, 5))
                SET(CURLOPT_PROXYTYPE, (long)CURLPROXY_SOCKS4);
            else if (!strncmp("socks5", proxy, 5))
                SET(CURLOPT_PROXYTYPE, (long)CURLPROXY_SOCKS5);
        }
        CURLcode code = curl_easy_perform(easy.get());
        long status = 0;
        require(curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE, &status) == CURLE_OK,
                "curl response status");
        require(fclose(response.release()) == 0, "complete response file close");
        printf("{\"curlCode\":%d,\"httpStatus\":%ld,\"proxies\":", (int)code, status);
        array(proxies.get());
        puts("}");
        return code == CURLE_OK && status == 200 ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        return 2;
    }
}
