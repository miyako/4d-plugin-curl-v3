#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "proxy.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
static CFMutableDictionaryRef settings;

// Interpose only in this test executable; do not read or modify host settings.
extern "C" CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef) {
    return static_cast<CFDictionaryRef>(CFRetain(settings));
}
#endif

static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class Configuration {
public:
#ifdef _WIN32
    HKEY root = NULL;
    HKEY internet = NULL;
    std::string path;
    Configuration() {
        path = "Software\\4d-plugin-curl-proxy-test-" + std::to_string(GetCurrentProcessId());
        require(RegCreateKeyExA(HKEY_CURRENT_USER, path.c_str(), 0, NULL, 0,
            KEY_ALL_ACCESS, NULL, &root, NULL) == ERROR_SUCCESS, "create isolated registry");
        require(RegCreateKeyExA(root,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0,
            NULL, 0, KEY_ALL_ACCESS, NULL, &internet, NULL) == ERROR_SUCCESS, "create settings");
        require(RegOverridePredefKey(HKEY_CURRENT_USER, root) == ERROR_SUCCESS, "redirect HKCU");
    }
    ~Configuration() {
        RegOverridePredefKey(HKEY_CURRENT_USER, NULL);
        RegCloseKey(internet);
        RegCloseKey(root);
        RegDeleteTreeA(HKEY_CURRENT_USER, path.c_str());
    }
    void clear() {
        const char* names[] = {"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"};
        for (auto name : names) {
            LSTATUS status = RegDeleteValueA(internet, name);
            require(status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND, "clear registry value");
        }
        HKEY connections;
        require(RegCreateKeyExA(internet, "Connections", 0, NULL, 0, KEY_ALL_ACCESS,
            NULL, &connections, NULL) == ERROR_SUCCESS, "open Connections");
        BYTE flags[12] = {};
        LSTATUS status = RegSetValueExA(connections, "DefaultConnectionSettings", 0,
            REG_BINARY, flags, sizeof(flags));
        RegCloseKey(connections);
        require(status == ERROR_SUCCESS, "clear PAC/WPAD flags");
    }
    void number(const char* name, int value) {
        DWORD number = value;
        require(RegSetValueExA(internet, name, 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&number), sizeof(number)) == ERROR_SUCCESS, "set DWORD");
    }
    void text(const char* name, const std::string& value) {
        require(RegSetValueExA(internet, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>(value.size() + 1)) == ERROR_SUCCESS, "set string");
    }
    void pac(const std::string& url) {
        text("AutoConfigURL", url);
        HKEY connections;
        require(RegOpenKeyExA(internet, "Connections", 0, KEY_SET_VALUE,
            &connections) == ERROR_SUCCESS, "open PAC flags");
        BYTE flags[12] = {};
        flags[8] = 4;
        LSTATUS status = RegSetValueExA(connections, "DefaultConnectionSettings", 0,
            REG_BINARY, flags, sizeof(flags));
        RegCloseKey(connections);
        require(status == ERROR_SUCCESS, "set PAC flag");
    }
#else
    Configuration() {
        settings = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        require(settings != NULL, "create synthetic settings");
    }
    ~Configuration() { CFRelease(settings); }
    void clear() { CFDictionaryRemoveAllValues(settings); }
    void number(const char* name, int value) {
        CFStringRef key = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
        CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &value);
        CFDictionarySetValue(settings, key, number);
        CFRelease(number);
        CFRelease(key);
    }
    void text(const char* name, const std::string& value) {
        CFStringRef key = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
        CFStringRef text = CFStringCreateWithCString(NULL, value.c_str(), kCFStringEncodingUTF8);
        CFDictionarySetValue(settings, key, text);
        CFRelease(text);
        CFRelease(key);
    }
#endif
};

static unsigned mismatches = 0;

static void expect(const char* name, const char* url, std::vector<std::string> expected) {
    pxProxyFactory* factory = px_proxy_factory_new();
    require(factory != NULL, "factory allocation");
    char** proxies = px_proxy_factory_get_proxies(factory, url);
    std::vector<std::string> actual;
    if (proxies) {
        for (size_t i = 0; proxies[i]; ++i) actual.push_back(proxies[i]);
        px_proxy_factory_free_proxies(proxies);
    }
    px_proxy_factory_free(factory);
    std::cout << name << ":";
    for (const auto& proxy : actual) std::cout << " " << proxy;
    std::cout << std::endl;
    if (actual != expected) {
        std::cerr << "Compatibility mismatch: " << name << std::endl;
        ++mismatches;
    }
}

int main(int argc, char** argv) {
    try {
        require(argc == 2, "expected local PAC fixture path");
        Configuration config;
        config.clear();
        expect("direct", "http://destination.invalid/", {"direct://"});
#ifdef _WIN32
        config.number("ProxyEnable", 1);
        config.text("ProxyServer", "http=proxy.invalid:8080;https=secure.invalid:8443;socks=socks.invalid:1080");
        expect("manual-http", "http://destination.invalid/", {"http://proxy.invalid:8080"});
        expect("manual-https", "https://destination.invalid/", {"https://secure.invalid:8443"});
        config.text("ProxyOverride", "bypass.invalid;<local>");
        expect("bypass-host", "http://bypass.invalid/", {"direct://"});
        expect("bypass-local", "http://intranet/", {"direct://"});
        config.text("ProxyOverride", "<local>");
        expect("bypass-local-only", "http://intranet/", {"direct://"});
        config.clear();
        config.number("ProxyEnable", 1);
        config.text("ProxyServer", "socks=socks.invalid:1080");
        expect("manual-socks", "http://destination.invalid/", {"socks://socks.invalid:1080"});
        config.clear();
        std::string local_path = argv[1];
        require(local_path.size() > 2 && local_path[1] == ':', "expected drive-qualified PAC fixture");
        config.pac("file://" + local_path.substr(2));
        expect("pac-no-builtin-runner", "http://destination.invalid/", {"direct://"});
#else
        config.number("HTTPEnable", 1);
        config.number("HTTPPort", 8080);
        config.text("HTTPProxy", "proxy.invalid");
        config.number("HTTPSEnable", 1);
        config.number("HTTPSPort", 8443);
        config.text("HTTPSProxy", "secure.invalid");
        expect("manual-http", "http://destination.invalid/", {"http://proxy.invalid:8080"});
        expect("manual-https", "https://destination.invalid/", {"http://secure.invalid:8443"});
        config.number("ExcludeSimpleHostnames", 1);
        expect("bypass-local", "http://intranet/", {"direct://"});
        const void* bypass[] = {CFSTR("bypass.invalid")};
        CFArrayRef exceptions = CFArrayCreate(NULL, bypass, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(settings, CFSTR("ExceptionsList"), exceptions);
        CFRelease(exceptions);
        expect("bypass-host", "http://bypass.invalid/", {"direct://"});
        config.clear();
        config.number("SOCKSEnable", 1);
        config.number("SOCKSPort", 1080);
        config.text("SOCKSProxy", "socks.invalid");
        expect("manual-socks", "http://destination.invalid/", {"socks://socks.invalid:1080"});
        config.clear();
        config.number("ProxyAutoConfigEnable", 1);
        config.text("ProxyAutoConfigURLString", std::string("file://") + argv[1]);
        expect("pac-order", "http://destination.invalid/",
            {"http://pac.invalid:3128", "socks5://socks.invalid:1080", "direct://"});
        expect("pac-direct", "http://bypass.invalid/", {"direct://"});
#endif
        expect("invalid-url", "not a URL", {"direct://"});
        return mismatches ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
