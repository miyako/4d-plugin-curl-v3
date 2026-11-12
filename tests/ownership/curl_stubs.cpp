// Deny-by-default synthetic replacements for the libcurl, libproxy and
// libiconv entry points the plugin links against. Transfers are scripted by
// HarnessScenario; anything the harness does not model aborts.

#include "curl/curl.h"
#include "proxy.h"
#include "iconv.h"
#include "curl_stubs.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <thread>

static void deny(const char *what) {
    fprintf(stderr, "DENIED boundary: %s\n", what);
    fflush(stderr);
    abort();
}

namespace {

typedef size_t (*data_fn)(char *, size_t, size_t, void *);

struct FakeEasy {
    data_fn write = nullptr, header = nullptr;
    void *writeData = nullptr, *headerData = nullptr;
};

struct FakeMulti {
    FakeEasy *easy = nullptr;
    int remaining = 0;
    bool started = false, done = false, reported = false;
    CURLMsg msg;
};

HarnessScenario gScenario;
int gEasyPerforms = 0, gMultiTransfers = 0;
std::set<FakeEasy *> gEasy;
std::set<FakeMulti *> gMulti;
std::set<struct curl_slist *> gSlists;
std::map<int, std::vector<std::string> > gSlistOptions;
std::map<int, long> gLongOptions;
std::map<int, std::string> gStringOptions;

FakeEasy *easyOf(CURL *c) {
    FakeEasy *e = (FakeEasy *)c;
    if (!gEasy.count(e)) deny("use of dead or foreign easy handle");
    return e;
}

FakeMulti *multiOf(CURLM *m) {
    FakeMulti *f = (FakeMulti *)m;
    if (!gMulti.count(f)) deny("use of dead or foreign multi handle");
    return f;
}

void deliver(FakeEasy *e) {
    if (!gScenario.header.empty()) {
        if (!e->header) deny("header data without CURLOPT_HEADERFUNCTION");
        std::string h = gScenario.header;
        if (e->header(&h[0], 1, h.size(), e->headerData) != h.size()) deny("header callback refused data");
    }
    if (!gScenario.body.empty()) {
        if (!e->write) deny("body data without CURLOPT_WRITEFUNCTION");
        std::string b = gScenario.body;
        if (e->write(&b[0], 1, b.size(), e->writeData) != b.size()) deny("write callback refused data");
    }
}

struct curl_slist *slistNode(const char *s) {
    struct curl_slist *n = (struct curl_slist *)malloc(sizeof(*n));
    n->data = strdup(s);
    n->next = nullptr;
    gSlists.insert(n);
    return n;
}

const char *const kProtocols[] = {"dict", "file", "ftp", "ftps", "http", "https", "sftp", nullptr};

}  // namespace

void harness_set_scenario(const HarnessScenario &s) { gScenario = s; }
int harness_easy_performs() { return gEasyPerforms; }
int harness_multi_transfers() { return gMultiTransfers; }
int harness_live_easy_handles() { return (int)gEasy.size(); }
int harness_live_slists() { return (int)gSlists.size(); }
std::vector<std::string> harness_slist_option(int option) { return gSlistOptions[option]; }
long harness_long_option(int option, long fallback) {
    auto it = gLongOptions.find(option);
    return it == gLongOptions.end() ? fallback : it->second;
}
std::string harness_string_option(int option) { return gStringOptions[option]; }
void harness_probe_denied_iconv() { iconv_open("utf-16", "utf-8"); }
void harness_probe_denied_proxy() { px_proxy_factory_get_proxies((pxProxyFactory *)0x1, "http://127.0.0.1/"); }

// --- easy ---------------------------------------------------------------

CURLcode curl_global_init(long) { return CURLE_OK; }
void curl_global_cleanup(void) {}

CURL *curl_easy_init(void) {
    FakeEasy *e = new FakeEasy();
    gEasy.insert(e);
    return (CURL *)e;
}

void curl_easy_cleanup(CURL *c) {
    FakeEasy *e = easyOf(c);
    gEasy.erase(e);
    delete e;
}

CURLcode curl_easy_setopt(CURL *c, CURLoption option, ...) {
    FakeEasy *e = easyOf(c);
    va_list ap;
    va_start(ap, option);
    int kind = (int)option / 10000;
    if (kind == 0) {
        gLongOptions[option] = va_arg(ap, long);
    } else if (kind == 1) {
        void *p = va_arg(ap, void *);
        switch (option) {
            case CURLOPT_WRITEDATA: e->writeData = p; break;
            case CURLOPT_HEADERDATA: e->headerData = p; break;
            case CURLOPT_CONNECT_TO: case CURLOPT_PROXYHEADER: case CURLOPT_HTTPHEADER:
            case CURLOPT_HTTP200ALIASES: case CURLOPT_RESOLVE: case CURLOPT_MAIL_RCPT:
            case CURLOPT_PREQUOTE: case CURLOPT_POSTQUOTE: case CURLOPT_QUOTE:
            case CURLOPT_TELNETOPTIONS: {
                std::vector<std::string> copy;
                for (struct curl_slist *n = (struct curl_slist *)p; n; n = n->next) {
                    if (!gSlists.count(n)) deny("setopt with dead slist");
                    copy.push_back(n->data);
                }
                gSlistOptions[option] = copy;
                break;
            }
            case CURLOPT_URL: case CURLOPT_USERAGENT: case CURLOPT_CUSTOMREQUEST: case CURLOPT_PROXY:
            case CURLOPT_USERNAME: case CURLOPT_PASSWORD: case CURLOPT_REFERER:
                gStringOptions[option] = p ? (const char *)p : "";
                break;
            default:
                break;
        }
    } else if (kind == 2) {
        data_fn fn = va_arg(ap, data_fn);
        if (option == CURLOPT_WRITEFUNCTION) e->write = fn;
        if (option == CURLOPT_HEADERFUNCTION) e->header = fn;
    } else if (kind == 3) {
        (void)va_arg(ap, curl_off_t);
    } else {
        (void)va_arg(ap, void *);
    }
    va_end(ap);
    return CURLE_OK;
}

CURLcode curl_easy_perform(CURL *c) {
    FakeEasy *e = easyOf(c);
    ++gEasyPerforms;
    deliver(e);
    return (CURLcode)gScenario.result;
}

CURLcode curl_easy_getinfo(CURL *c, CURLINFO info, ...) {
    easyOf(c);
    va_list ap;
    va_start(ap, info);
    void *out = va_arg(ap, void *);
    va_end(ap);
    static char url[] = "ftp://127.0.0.1/synthetic/";
    static char text[] = "synthetic";
    static char certLines[2][2][32] = {{"Subject:CN=one", "Issuer:CN=root"}, {"Subject:CN=two", "Issuer:CN=root"}};
    static struct curl_slist certs[2][2];
    static struct curl_slist *certHeads[2];
    static struct curl_certinfo ci;
    switch (info & CURLINFO_TYPEMASK) {
        case CURLINFO_STRING:
            *(char **)out = (info == CURLINFO_EFFECTIVE_URL) ? url : text;
            return CURLE_OK;
        case CURLINFO_LONG:
            *(long *)out = (info == CURLINFO_FILETIME) ? 0 : 200;
            return CURLE_OK;
        case CURLINFO_OFF_T:
            *(curl_off_t *)out = 1;
            return CURLE_OK;
        case CURLINFO_DOUBLE:
            *(double *)out = 0;
            return CURLE_OK;
        case CURLINFO_SOCKET:
            *(curl_socket_t *)out = CURL_SOCKET_BAD;
            return CURLE_OK;
        case CURLINFO_SLIST:
            if (info != CURLINFO_CERTINFO) return CURLE_UNKNOWN_OPTION;
            // libcurl reports CURLE_OK with zero certificates unless CERTINFO data exists
            memset(&ci, 0, sizeof(ci));
            if (gScenario.certinfo) {
                for (int i = 0; i < 2; ++i) {
                    certs[i][0].data = certLines[i][0];
                    certs[i][0].next = &certs[i][1];
                    certs[i][1].data = certLines[i][1];
                    certs[i][1].next = nullptr;
                    certHeads[i] = &certs[i][0];
                }
                ci.num_of_certs = 2;
                ci.certinfo = certHeads;
            }
            *(struct curl_certinfo **)out = &ci;
            return CURLE_OK;
        default:
            return CURLE_UNKNOWN_OPTION;
    }
}

char *curl_easy_escape(CURL *, const char *s, int len) { return strndup(s, len > 0 ? (size_t)len : strlen(s)); }
char *curl_easy_unescape(CURL *, const char *s, int len, int *outlen) {
    char *r = strndup(s, len > 0 ? (size_t)len : strlen(s));
    if (outlen) *outlen = (int)strlen(r);
    return r;
}
void curl_free(void *p) { free(p); }
time_t curl_getdate(const char *, const time_t *) { return 0; }

struct curl_slist *curl_slist_append(struct curl_slist *list, const char *s) {
    struct curl_slist *n = slistNode(s);
    if (!list) return n;
    struct curl_slist *last = list;
    while (last->next) last = last->next;
    last->next = n;
    return list;
}

void curl_slist_free_all(struct curl_slist *list) {
    while (list) {
        struct curl_slist *next = list->next;
        if (!gSlists.erase(list)) deny("double or foreign slist free");
        free(list->data);
        free(list);
        list = next;
    }
}

curl_version_info_data *curl_version_info(CURLversion) {
    static curl_version_info_data d;
    memset(&d, 0, sizeof(d));
    d.age = CURLVERSION_NOW;
    d.version = "8.0.0-synthetic";
    d.version_num = 0x080000;
    d.host = "harness";
    d.ssl_version = "SyntheticSSL";
    d.libz_version = "1.0";
    d.protocols = kProtocols;
    d.libidn = "idn";
    d.libssh_version = "ssh";
    d.brotli_version = "brotli";
    d.nghttp2_version = "nghttp2";
    d.zstd_version = "zstd";
    return &d;
}

// --- multi --------------------------------------------------------------

CURLM *curl_multi_init(void) {
    FakeMulti *m = new FakeMulti();
    gMulti.insert(m);
    return (CURLM *)m;
}

CURLMcode curl_multi_cleanup(CURLM *mh) {
    FakeMulti *m = multiOf(mh);
    if (m->easy) deny("multi cleanup with an attached easy handle");
    gMulti.erase(m);
    delete m;
    return CURLM_OK;
}

CURLMcode curl_multi_add_handle(CURLM *mh, CURL *c) {
    FakeMulti *m = multiOf(mh);
    if (m->easy) deny("second easy handle on one multi handle");
    m->easy = easyOf(c);
    m->remaining = gScenario.ticks;
    ++gMultiTransfers;
    return CURLM_OK;
}

CURLMcode curl_multi_remove_handle(CURLM *mh, CURL *c) {
    FakeMulti *m = multiOf(mh);
    if (m->easy != easyOf(c)) deny("remove of a handle that is not attached");
    m->easy = nullptr;
    return CURLM_OK;
}

CURLMcode curl_multi_perform(CURLM *mh, int *running) {
    FakeMulti *m = multiOf(mh);
    if (!m->easy) deny("perform without an easy handle");
    if (!m->started) {
        m->started = true;
        deliver(m->easy);
    } else if (m->remaining > 0) {
        if (gScenario.tickMs) std::this_thread::sleep_for(std::chrono::milliseconds(gScenario.tickMs));
        --m->remaining;
    }
    m->done = m->remaining == 0;
    *running = m->done ? 0 : 1;
    return CURLM_OK;
}

CURLMcode curl_multi_timeout(CURLM *mh, long *timeout) {
    multiOf(mh);
    *timeout = -1;
    return CURLM_OK;
}

CURLMcode curl_multi_fdset(CURLM *mh, fd_set *, fd_set *, fd_set *, int *maxfd) {
    multiOf(mh);
    *maxfd = -1;  // no sockets: the plugin takes its DELAY PROCESS path, never select()
    return CURLM_OK;
}

CURLMsg *curl_multi_info_read(CURLM *mh, int *queued) {
    FakeMulti *m = multiOf(mh);
    *queued = 0;
    if (!m->done || m->reported) return nullptr;
    m->reported = true;
    m->msg.msg = CURLMSG_DONE;
    m->msg.easy_handle = (CURL *)m->easy;
    m->msg.data.result = (CURLcode)gScenario.result;
    return &m->msg;
}

// --- libproxy / libiconv --------------------------------------------------

pxProxyFactory *px_proxy_factory_new(void) { return (pxProxyFactory *)0x1; }
void px_proxy_factory_free(pxProxyFactory *) {}
char **px_proxy_factory_get_proxies(pxProxyFactory *, const char *) { deny("px_proxy_factory_get_proxies"); return nullptr; }
void px_proxy_factory_free_proxies(char **) { deny("px_proxy_factory_free_proxies"); }

extern "C" {
libiconv_t libiconv_open(const char *, const char *) { deny("libiconv_open"); return (libiconv_t)-1; }
size_t libiconv(libiconv_t, char **, size_t *, char **, size_t *) { deny("libiconv"); return (size_t)-1; }
int libiconv_close(libiconv_t) { deny("libiconv_close"); return -1; }
}
