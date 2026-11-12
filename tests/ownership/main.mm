// Ownership regression harness for 4D plugin curl-v3.
//
// Links the real 4DPlugin-cURL.cpp, support/4DPlugin-JSON.cpp, the bundled
// ftpparse.c and the unchanged bundled 4D Plugin API (4DPluginAPI.c and the
// C_TEXT/C_BLOB/C_LONGINT classes) against
//   * a fake 4D engine (the Call4D callback) that tracks every unistring,
//     object/collection reference, picture and handle it hands out, and
//   * a synthetic libcurl/libproxy/libiconv boundary (curl_stubs.cpp) that
//     scripts transfers without any socket, DNS lookup or network access.
// Each named test runs in its own process (`--test NAME`) and fails if any
// engine-owned value is left alive or released twice. `--probe NAME` runs an
// expected-crash probe that proves the detectors fire.

#import <Foundation/Foundation.h>

#include "4DPluginAPI.h"
#include "PrivateTypes.h"
#include "EntryPoints.h"
#include "4DPlugin-JSON.h"
#include "curl/curl.h"
#include "curl_stubs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// fake engine
// ---------------------------------------------------------------------------

namespace fake {

static void die(const char *what) {
    fprintf(stderr, "FAKE ENGINE ABORT: %s\n", what);
    fflush(stderr);
    abort();
}

struct Pic {
    int refs;
    std::vector<uint8_t> bytes;
};

struct Obj;

struct Value {
    int kind = eVK_Undefined;
    double real = 0;
    char boolean = 0;
    PA_long32 longint = 0;
    CUTF16String str;
    Obj *obj = nullptr;
    Pic *pic = nullptr;
};

struct Obj {
    int refs;
    bool collection;
    std::map<CUTF16String, Value> props;
    std::vector<Value> elems;
};

static std::set<PA_Unichar *> liveStrings;
static std::set<Obj *> liveObjs;
static std::set<Pic *> livePics;
static std::set<PA_Handle> liveHandles;
static bool failNextGet = false;

static PA_Unistring makeString(const PA_Unichar *src, size_t len) {
    PA_Unichar *buf = new PA_Unichar[len + 1];
    if (len) memcpy(buf, src, len * sizeof(PA_Unichar));
    buf[len] = 0;
    liveStrings.insert(buf);
    PA_Unistring u;
    memset(&u, 0, sizeof(u));
    u.fLength = (PA_long32)len;
    u.fString = buf;
    return u;
}

static void disposeString(PA_Unistring u) {  // by value: SDK structs are packed
    PA_Unichar *chars = u.fString;
    if (!chars) return;
    if (!liveStrings.erase(chars)) die("double or foreign unistring dispose");
    delete[] chars;
}

static Obj *checkObj(void *p) {
    Obj *o = (Obj *)p;
    if (!liveObjs.count(o)) die("use of dead or foreign object/collection reference");
    return o;
}

static Pic *checkPic(void *p) {
    Pic *pic = (Pic *)p;
    if (!livePics.count(pic)) die("use of dead or foreign picture");
    return pic;
}

static Obj *newObj(bool collection) {
    Obj *o = new Obj();
    o->refs = 1;
    o->collection = collection;
    liveObjs.insert(o);
    return o;
}

static void releaseObj(Obj *o);
static void releasePic(Pic *p) {
    checkPic(p);
    if (--p->refs == 0) {
        livePics.erase(p);
        delete p;
    }
}

static void releaseValue(Value &v) {
    if (v.obj) releaseObj(v.obj);
    if (v.pic) releasePic(v.pic);
    v.obj = nullptr;
    v.pic = nullptr;
}

static void releaseObj(Obj *o) {
    checkObj(o);
    if (--o->refs == 0) {
        for (auto &kv : o->props) releaseValue(kv.second);
        for (auto &e : o->elems) releaseValue(e);
        liveObjs.erase(o);
        delete o;
    }
}

static CUTF16String keyOf(PA_Unistring u) {
    PA_Unichar *chars = u.fString;
    return CUTF16String(chars, chars ? u.fLength : 0);
}

// EX_SET_OBJ_VALUE copies the incoming value: strings are duplicated,
// references are retained. The caller keeps its own variable.
static Value valueFromVar(const PA_Variable *v) {
    Value out;
    out.kind = v->fType;
    switch (v->fType) {
        case eVK_Unistring:
            out.str = keyOf(v->uValue.fString);
            break;
        case eVK_Real: out.real = v->uValue.fReal; break;
        case eVK_Boolean: out.boolean = v->uValue.fBoolean; break;
        case eVK_Longint: out.longint = v->uValue.fLongint; break;
        case eVK_Object:
        case eVK_Collection:
            if (PA_ObjectRef ref = v->uValue.fObject) {
                out.obj = checkObj(ref);
                out.obj->refs++;
            }
            break;
        case eVK_Picture:
            if (PA_Picture pic = v->uValue.fPicture) {
                out.pic = checkPic(pic);
                out.pic->refs++;
            }
            break;
        case eVK_Undefined:
        case (char)eVK_Null:
            break;
        default:
            die("set of unknown variable kind");
    }
    return out;
}

// EX_GET_OBJ_VALUE returns an owned value ("The PA_Variable should be
// cleared after use").
static void varFromValue(const Value &val, PA_Variable *out) {
    memset(out, 0, sizeof(*out));
    out->fType = (char)val.kind;
    switch (val.kind) {
        case eVK_Unistring:
            out->uValue.fString = makeString(val.str.data(), val.str.size());
            break;
        case eVK_Real: out->uValue.fReal = val.real; break;
        case eVK_Boolean: out->uValue.fBoolean = val.boolean; break;
        case eVK_Longint: out->uValue.fLongint = val.longint; break;
        case eVK_Object:
        case eVK_Collection:
            if (val.obj) val.obj->refs++;
            out->uValue.fObject = val.obj;
            break;
        case eVK_Picture:
            if (val.pic) val.pic->refs++;
            out->uValue.fPicture = val.pic;
            break;
        default:
            break;
    }
}

static void clearVar(PA_Variable *v) {
    switch (v->fType) {
        case eVK_Unistring:
            disposeString(v->uValue.fString);
            break;
        case eVK_Picture:
            if (PA_Picture pic = v->uValue.fPicture) releasePic((Pic *)pic);
            break;
        case eVK_Object:
        case eVK_Collection:
            if (PA_ObjectRef ref = v->uValue.fObject) releaseObj((Obj *)ref);
            break;
        case eVK_Real:
        case eVK_Boolean:
        case eVK_Longint:
        case eVK_Undefined:
        case (char)eVK_Null:
            break;
        default:
            die("clear of unknown or poisoned variable kind");
    }
    memset(&v->uValue, 0, sizeof(v->uValue));
    v->fType = eVK_Undefined;
}

static void setValue(Obj *o, const EngineBlock *eb, Value val) {
    if (eb->fShort == eVK_Object) {
        if (o->collection) die("object property set on a collection");
        Value &slot = o->props[keyOf(eb->fUniString1)];
        releaseValue(slot);
        slot = val;
    } else if (eb->fShort == eVK_Collection) {
        if (!o->collection) die("collection element set on an object");
        if (eb->fLongint < 0) die("negative collection index");
        size_t idx = (size_t)eb->fLongint;
        if (idx >= o->elems.size()) o->elems.resize(idx + 1);
        releaseValue(o->elems[idx]);
        o->elems[idx] = val;
    } else {
        die("EX_SET_OBJ_VALUE with unknown target kind");
    }
}

static void getValue(Obj *o, EngineBlock *eb, PA_Variable *out) {
    if (failNextGet) {
        failNextGet = false;
        memset(out, 0xA5, sizeof(*out));
        eb->fError = 1;
        return;
    }
    Value missing;
    if (eb->fShort == eVK_Object) {
        auto it = o->props.find(keyOf(eb->fUniString1));
        varFromValue(it == o->props.end() ? missing : it->second, out);
    } else if (eb->fShort == eVK_Collection) {
        if (eb->fLongint == -1) {
            CUTF16String length = {'l', 'e', 'n', 'g', 't', 'h'};
            if (keyOf(eb->fUniString1) != length) die("collection pseudo-property is not length");
            memset(out, 0, sizeof(*out));
            out->fType = eVK_Longint;
            out->uValue.fLongint = (PA_long32)o->elems.size();
        } else {
            size_t idx = (size_t)eb->fLongint;
            varFromValue(idx < o->elems.size() ? o->elems[idx] : missing, out);
        }
    } else {
        die("EX_GET_OBJ_VALUE with unknown target kind");
    }
}

// --- callback model ---------------------------------------------------------

enum CallbackResult { kResultNone, kResultFalse, kResultTrue, kResultText, kResultObject, kResultFail };

static const PA_long32 kCallbackMethodID = 7;
static CallbackResult methodResult = kResultNone;
static bool executeMethodAbort = false;
static int methodCalls = 0;
static int executeMethodCalls = 0;
static int delayCalls = 0;
static std::vector<CUTF16String> seenUserInfo;
static std::vector<size_t> seenCertLines;

static void requireLiveText(const PA_Variable *v, const char *what) {
    if (v->fType != eVK_Unistring) die(what);
    PA_Unichar *chars = v->uValue.fString.fString;
    if (!chars || !liveStrings.count(chars)) die("callback parameter text is dead");
}

static Obj *requireLiveObject(const PA_Variable *v, const char *what) {
    if (v->fType != eVK_Object) die(what);
    PA_ObjectRef ref = v->uValue.fObject;
    if (!ref) die("callback transferInfo object is null");
    return checkObj(ref);
}

static void recordTransferInfo(Obj *o) {
    CUTF16String key = {'c', 'e', 'r', 't', 'I', 'n', 'f', 'o'};
    auto it = o->props.find(key);
    if (it == o->props.end() || it->second.kind != eVK_Collection || !it->second.obj) die("transferInfo without certInfo collection");
    for (auto &e : it->second.obj->elems)
        if (e.kind != eVK_Unistring) die("certInfo element is not text");
    seenCertLines.push_back(it->second.obj->elems.size());
}

// EX_CALL_BY_PROCID: slot 0 is the method result, the parameters follow as
// shallow copies of the caller's variables.
static void callMethod(EngineBlock *eb) {
    PA_Handle h = eb->fHandle;
    if (!liveHandles.count(h)) die("EX_CALL_BY_PROCID with dead handle");
    if (eb->fParam1 != kCallbackMethodID) die("EX_CALL_BY_PROCID with unknown method id");
    if (eb->fParam2 != 2) die("callback method arity");
    PA_Variable *slots = (PA_Variable *)*h;
    recordTransferInfo(requireLiveObject(&slots[1], "callback $1 is not an object"));
    requireLiveText(&slots[2], "callback $2 is not text");
    seenUserInfo.push_back(keyOf(slots[2].uValue.fString));
    ++methodCalls;
    PA_Variable *result = &slots[0];
    switch (methodResult) {
        case kResultNone:
            break;
        case kResultFalse:
        case kResultTrue:
            result->fType = eVK_Boolean;
            result->uValue.fBoolean = methodResult == kResultTrue;
            break;
        case kResultText: {
            const PA_Unichar t[] = {'o', 'k'};
            result->fType = eVK_Unistring;
            result->uValue.fString = makeString(t, 2);
            break;
        }
        case kResultObject:
            result->fType = eVK_Object;
            result->uValue.fObject = newObj(false);
            break;
        case kResultFail:
            // failed call: the result slot holds nothing the caller may release
            memset(result, 0xA5, sizeof(*result));
            eb->fError = 1;
            break;
    }
}

static void executeCommand(EngineBlock *eb) {
    PA_Variable **params = (PA_Variable **)eb->fPtr1;
    PA_Variable *result = (PA_Variable *)eb->fPtr2;
    if (result->fType != eVK_Undefined) die("command result variable is not empty");
    switch (eb->fParam1) {
        case 1471:
            if (eb->fParam2 != 0) die("New object with parameters");
            result->fType = eVK_Object;
            result->uValue.fObject = newObj(false);
            break;
        case 1472:
            if (eb->fParam2 != 0) die("New collection with parameters");
            result->fType = eVK_Collection;
            result->uValue.fCollection = newObj(true);
            break;
        case 1231: {
            if (eb->fParam2 != 2) die("OB Is defined arity");
            if (params[0]->fType != eVK_Object || params[1]->fType != eVK_Unistring) die("OB Is defined argument kinds");
            PA_ObjectRef ref0 = params[0]->uValue.fObject;
            Obj *o = checkObj(ref0);
            auto it = o->props.find(keyOf(params[1]->uValue.fString));
            result->fType = eVK_Boolean;
            result->uValue.fBoolean = (it != o->props.end() && it->second.kind != eVK_Undefined) ? 1 : 0;
            break;
        }
        case 323:  // DELAY PROCESS(process; ticks)
            if (eb->fParam2 != 2 || params[0]->fType != eVK_Longint || params[1]->fType != eVK_Real) die("DELAY PROCESS arguments");
            ++delayCalls;
            break;
        case 672:  // Process aborted
            if (eb->fParam2 != 0) die("Process aborted arity");
            result->fType = eVK_Boolean;
            result->uValue.fBoolean = 0;
            break;
        case 1007: {  // EXECUTE METHOD(name; result; transferInfo; userInfo)
            if (eb->fParam2 != 4) die("EXECUTE METHOD arity");
            requireLiveText(params[0], "EXECUTE METHOD name is not text");
            if (params[1]->fType != eVK_Boolean) die("EXECUTE METHOD result variable is not boolean");
            recordTransferInfo(requireLiveObject(params[2], "EXECUTE METHOD $1 is not an object"));
            requireLiveText(params[3], "EXECUTE METHOD $2 is not text");
            seenUserInfo.push_back(keyOf(params[3]->uValue.fString));
            ++executeMethodCalls;
            params[1]->uValue.fBoolean = executeMethodAbort ? 1 : 0;
            break;
        }
        default:
            fprintf(stderr, "unexpected command id %ld\n", (long)eb->fParam1);
            die("unexpected PA_ExecuteCommandByID");
    }
}

static PA_Handle newHandle(const void *bytes, size_t len) {
    PA_Handle h = new char *;
    *h = (char *)calloc(1, len ? len : 1);
    if (len && bytes) memcpy(*h, bytes, len);
    liveHandles.insert(h);
    return h;
}

static std::map<PA_Handle, size_t> handleSizes;

static void handleManager(EngineBlock *eb) {
    switch (eb->fParam1) {
        case 1: {
            size_t len = eb->fParam2 > 0 ? (size_t)eb->fParam2 : 0;
            PA_Handle h = newHandle(nullptr, len);
            handleSizes[h] = len;
            eb->fHandle = h;
            break;
        }
        case 2: {
            PA_Handle h = eb->fHandle;
            if (!liveHandles.erase(h)) die("double or foreign handle dispose");
            handleSizes.erase(h);
            free(*h);
            delete h;
            break;
        }
        case 4: {
            PA_Handle h = eb->fHandle;
            if (!liveHandles.count(h)) die("size of dead handle");
            eb->fParam2 = (sLONG_PTR)handleSizes[h];
            break;
        }
        case 5: {
            PA_Handle h = eb->fHandle;
            if (!liveHandles.count(h)) die("lock of dead handle");
            eb->fParam3 = (sLONG_PTR)*h;
            break;
        }
        case 6: {
            PA_Handle h = eb->fHandle;
            if (!liveHandles.count(h)) die("unlock of dead handle");
            break;
        }
        default:
            die("unexpected handle manager operation");
    }
}

static std::vector<uint8_t> handleBytes(PA_Handle h) {
    if (!h) return std::vector<uint8_t>();
    if (!liveHandles.count(h)) die("read of dead handle");
    return std::vector<uint8_t>(*h, *h + handleSizes[h]);
}

static PA_Handle blobHandle(const std::string &s) {
    PA_Handle h = newHandle(s.data(), s.size());
    handleSizes[h] = s.size();
    return h;
}

static std::map<CUTF16String, PA_long32> methodIDs;

static void call4d(short selector, EngineBlock *eb) {
    switch (selector) {
        case EX_GET_INFORMATION:
            if (eb->fParam3 != (sLONG_PTR)'FAST') die("unexpected EX_GET_INFORMATION");
            eb->fParam2 = 0x00001900;
            break;
        case EX_HANDLE_MANAGER:
            handleManager(eb);
            break;
        case EX_CREATE_UNISTRING: {
            const PA_Unichar *src = (const PA_Unichar *)eb->fHandle;
            size_t len = 0;
            while (src[len]) ++len;
            eb->fUniString1 = makeString(src, len);
            break;
        }
        case EX_DISPOSE_UNISTRING:
            disposeString(eb->fUniString1);
            break;
        case EX_SET_UNISTRING: {
            // replaces the text in place: the previous buffer is released
            const PA_Unichar *src = (const PA_Unichar *)eb->fHandle;
            size_t len = 0;
            while (src[len]) ++len;
            PA_Unistring fresh = makeString(src, len);
            disposeString(eb->fUniString1);
            eb->fUniString1 = fresh;
            break;
        }
        case EX_VARIABLE_TO_STRING: {
            // Treated as a borrowed view of the variable's own string; the
            // SDK does not document ownership of this result.
            PA_Variable *v = (PA_Variable *)eb->fHandle;
            if (v->fType != eVK_Unistring) die("EX_VARIABLE_TO_STRING on non-text");
            PA_Unichar *chars = v->uValue.fString.fString;
            if (chars && !liveStrings.count(chars)) die("read of dead unistring");
            eb->fUniString1 = v->uValue.fString;
            break;
        }
        case EX_CREATE_PICTURE: {
            Pic *p = new Pic();
            p->refs = 1;
            if (eb->fParam1 > 0) p->bytes.assign((uint8_t *)eb->fPtr1, (uint8_t *)eb->fPtr1 + eb->fParam1);
            livePics.insert(p);
            eb->fPicture = p;
            break;
        }
        case EX_DISPOSE_PICTURE:
            if (PA_Picture pic = eb->fPicture) releasePic((Pic *)pic);
            break;
        case EX_CLEAR_VARIABLE:
            clearVar((PA_Variable *)eb->fPtr1);
            break;
        case EX_SET_OBJ_VALUE:
            setValue(checkObj(eb->fPtr1), eb, valueFromVar((const PA_Variable *)eb->fPtr2));
            break;
        case EX_GET_OBJ_VALUE:
            getValue(checkObj(eb->fPtr1), eb, (PA_Variable *)eb->fPtr2);
            break;
        case EX_EXECUTE_COMMAND_BY_ID:
            executeCommand(eb);
            break;
        case EX_CONVERT_STRING:
            // FromUserData (PA_SetBlobParameter): a new engine handle with a copy of the bytes
            if (eb->fParam1 != 5) die("unexpected EX_CONVERT_STRING mode");
        {
            PA_Handle h = newHandle((const void *)eb->fParam3, (size_t)eb->fParam4);
            handleSizes[h] = (size_t)eb->fParam4;
            eb->fHandle = h;
        }
            break;
        case EX_GET_METHOD_ID: {
            size_t len = 0;
            while (len < 255 && eb->fUName[len]) ++len;
            auto it = methodIDs.find(CUTF16String(eb->fUName, len));
            eb->fParam1 = it == methodIDs.end() ? 0 : it->second;
            break;
        }
        case EX_CURRENT_PROCESS_NUMBER:
            eb->fParam1 = 5;
            break;
        case EX_YIELD_ABSOLUTE:
            break;
        case EX_CALL_BY_PROCID:
            callMethod(eb);
            break;
        default:
            fprintf(stderr, "unexpected engine selector %d\n", (int)selector);
            die("unexpected engine selector");
    }
}

struct Counts {
    size_t strings, objs, pics, handles;
    bool operator==(const Counts &o) const {
        return strings == o.strings && objs == o.objs && pics == o.pics && handles == o.handles;
    }
};

static Counts snap() {
    return Counts{liveStrings.size(), liveObjs.size(), livePics.size(), liveHandles.size()};
}

// Seed a property without going through the helpers under test.
static void seed(PA_ObjectRef obj, const char16_t *key, const Value &v) {
    Obj *o = checkObj(obj);
    std::u16string k(key);
    Value copy = v;
    if (copy.obj) copy.obj->refs++;
    if (copy.pic) copy.pic->refs++;
    Value &slot = o->props[CUTF16String(k.begin(), k.end())];
    releaseValue(slot);
    slot = copy;
}

static const Value *prop(void *obj, const char16_t *key) {
    Obj *o = checkObj(obj);
    std::u16string k(key);
    auto it = o->props.find(CUTF16String(k.begin(), k.end()));
    return it == o->props.end() ? nullptr : &it->second;
}

}  // namespace fake

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

static bool gOk = true;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            fprintf(stderr, "  check failed: %s (line %d)\n", #cond, __LINE__);  \
            gOk = false;                                                         \
        }                                                                        \
    } while (0)

static CUTF16String U(const char16_t *s) {
    std::u16string t(s);
    return CUTF16String(t.begin(), t.end());
}

static fake::Value textValue(const char16_t *s) {
    fake::Value v;
    v.kind = eVK_Unistring;
    v.str = U(s);
    return v;
}

static fake::Value realValue(double d) {
    fake::Value v;
    v.kind = eVK_Real;
    v.real = d;
    return v;
}

static fake::Value boolValue(bool b) {
    fake::Value v;
    v.kind = eVK_Boolean;
    v.boolean = b ? 1 : 0;
    return v;
}

static void checkText(void *obj, const char16_t *key, const char16_t *expected) {
    const fake::Value *v = fake::prop(obj, key);
    CHECK(v != nullptr);
    if (!v) return;
    CHECK(v->kind == eVK_Unistring);
    CHECK(v->str == U(expected));
}

struct TextCase {
    const char *name;
    const char *utf8;
    const wchar_t *wide;
    const char16_t *utf16;
};

static const TextCase kTextCases[] = {
    {"ascii", "abc", L"abc", u"abc"},
    {"bmp", u8"\u65E5\u672C\u8A9E", L"\u65E5\u672C\u8A9E", u"\u65E5\u672C\u8A9E"},
    {"supplementary", u8"a\U0001F600b", L"a\U0001F600b", u"a\U0001F600b"},
    {"empty", "", L"", u""},
};

typedef std::function<void(PA_ObjectRef, const TextCase &)> TextSetter;

static void runSetterCase(const TextSetter &setter, const TextCase &tc) {
    PA_ObjectRef obj = PA_CreateObject();
    setter(obj, tc);
    checkText(obj, u"k", tc.utf16);
    PA_DisposeObject(obj);
}

static void runGetTextCase(const TextCase &tc) {
    PA_ObjectRef obj = PA_CreateObject();
    fake::seed(obj, u"k", textValue(tc.utf16));
    CUTF8String out((const uint8_t *)"sentinel");
    CHECK(ob_get_a(obj, L"k", &out));
    CHECK(std::string(out.begin(), out.end()) == std::string(tc.utf8));
    PA_DisposeObject(obj);
}

static void *dispatch(PA_long32 selector) {
    void *noParams[1] = {nullptr};
    void *data = nullptr;
    void *result = nullptr;
    FourDPackex(selector, noParams, &data, &result);
    return result;
}

static fake::Value objectValue() {
    fake::Value v;
    v.kind = eVK_Object;
    v.obj = fake::newObj(false);  // seeded values take their own reference; see makeCollection
    return v;
}

// A collection built directly in the fake engine (not through the helpers under test).
static PA_CollectionRef makeCollection(std::vector<fake::Value> elems) {
    fake::Obj *c = fake::newObj(true);
    c->elems = elems;  // the elements' references move into the collection
    return (PA_CollectionRef)c;
}

static void seedCollection(PA_ObjectRef obj, const char16_t *key, PA_CollectionRef col) {
    fake::Value v;
    v.kind = eVK_Collection;
    v.obj = (fake::Obj *)col;
    fake::seed(obj, key, v);
    PA_DisposeCollection(col);
}

static PA_ObjectRef baseOptions(const char16_t *url, bool atomic) {
    PA_ObjectRef opts = PA_CreateObject();
    fake::seed(opts, u"URL", textValue(url));
    fake::seed(opts, u"PRIVATE", textValue(u"user-info"));
    if (atomic) fake::seed(opts, u"ATOMIC", boolValue(true));
    return opts;
}

static PA_ObjectRef runCurl(PA_ObjectRef opts, const char16_t *callback, std::vector<uint8_t> *response) {
    PA_Handle request = nullptr;
    PA_Handle responseHandle = nullptr;
    PA_Unistring cb = PA_CreateUnistring((PA_Unichar *)callback);
    void *p[4] = {&opts, &request, &responseHandle, &cb};
    void *data = nullptr;
    PA_ObjectRef result = nullptr;
    FourDPackex(5, p, &data, &result);
    *response = fake::handleBytes(responseHandle);
    if (responseHandle) PA_DisposeHandle(responseHandle);
    PA_DisposeUnistring(&cb);
    CHECK(harness_live_easy_handles() == 0);
    CHECK(harness_live_slists() == 0);
    return result;
}

static PA_ObjectRef runFtp(PA_long32 selector, PA_ObjectRef opts, const char16_t *callback) {
    PA_Unistring cb = PA_CreateUnistring((PA_Unichar *)callback);
    void *p[2] = {&opts, &cb};
    void *data = nullptr;
    PA_ObjectRef result = nullptr;
    FourDPackex(selector, p, &data, &result);
    PA_DisposeUnistring(&cb);
    CHECK(harness_live_easy_handles() == 0);
    CHECK(harness_live_slists() == 0);
    return result;
}

static CUTF16String callText(PA_long32 selector, const char16_t *input) {
    PA_Unistring in = PA_CreateUnistring((PA_Unichar *)input);
    PA_Unistring out = PA_CreateUnistring((PA_Unichar *)u"");
    PA_Unistring *outPtr = &out;
    void *p[1] = {&in};
    void *data = nullptr;
    FourDPackex(selector, p, &data, &outPtr);
    CUTF16String got = fake::keyOf(out);
    PA_DisposeUnistring(&in);
    PA_DisposeUnistring(&out);
    CHECK(harness_live_easy_handles() == 0);
    return got;
}

static void checkResult(PA_ObjectRef ret, int status, size_t certLines) {
    CHECK(ret != NULL);
    if (!ret) return;
    const fake::Value *st = fake::prop(ret, u"status");
    CHECK(st && st->kind == eVK_Real && st->real == status);
    const fake::Value *hi = fake::prop(ret, u"headerInfo");
    CHECK(hi && hi->kind == eVK_Unistring);
    const fake::Value *ti = fake::prop(ret, u"transferInfo");
    CHECK(ti && ti->kind == eVK_Object && ti->obj);
    if (!ti || !ti->obj) return;
    const fake::Value *ci = fake::prop(ti->obj, u"certInfo");
    CHECK(ci && ci->kind == eVK_Collection && ci->obj);
    if (ci && ci->obj) {
        CHECK(ci->obj->elems.size() == certLines);
        for (auto &e : ci->obj->elems) CHECK(e.kind == eVK_Unistring && !e.str.empty());
    }
}

static void checkCallbackSeen(size_t calls, size_t certLines) {
    CHECK(fake::seenUserInfo.size() == calls);
    for (auto &u : fake::seenUserInfo) CHECK(u == U(u"user-info"));
    CHECK(fake::seenCertLines.size() == calls);
    for (size_t n : fake::seenCertLines) CHECK(n == certLines);
}

static PA_ObjectRef runCallbackTransfer(const char16_t *method, int ticks, bool certinfo) {
    HarnessScenario s;
    s.ticks = ticks;
    s.tickMs = 120;  // above the plugin's 100 ms callback throttle
    s.body = "x";
    s.certinfo = certinfo;
    harness_set_scenario(s);
    PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", false);
    std::vector<uint8_t> response;
    PA_ObjectRef ret = runCurl(opts, method, &response);
    CHECK(std::string(response.begin(), response.end()) == "x");
    CHECK(harness_multi_transfers() == 1);
    PA_DisposeObject(opts);
    return ret;
}

typedef std::map<std::string, std::function<void()> > TestMap;

static TextSetter setterFor(const std::string &overload) {
    if (overload == "set_s_wide")
        return [](PA_ObjectRef o, const TextCase &tc) { ob_set_s(o, L"k", tc.utf8); };
    if (overload == "set_s_narrow")
        return [](PA_ObjectRef o, const TextCase &tc) { ob_set_s(o, "k", tc.utf8); };
    if (overload == "set_a_wchar")
        return [](PA_ObjectRef o, const TextCase &tc) { ob_set_a(o, L"k", tc.wide); };
    return [](PA_ObjectRef o, const TextCase &tc) {
        CUTF16String v = U(tc.utf16);
        ob_set_a(o, L"k", &v);
    };
}

static TestMap buildTests() {
    TestMap t;

    const char *overloads[] = {"set_s_wide", "set_s_narrow", "set_a_wchar", "set_a_utf16"};
    for (const char *ov : overloads) {
        for (const TextCase &tc : kTextCases) {
            std::string name = std::string(ov) + "_" + tc.name;
            TextSetter setter = setterFor(ov);
            const TextCase *ptc = &tc;
            t[name] = [setter, ptc]() { runSetterCase(setter, *ptc); };
        }
    }

    t["control_set_s_null_value"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        ob_set_s(obj, L"k", (const char *)NULL);
        CHECK(fake::prop(obj, u"k") == nullptr);
        PA_DisposeObject(obj);
    };

    t["set_p_picture"] = []() {
        uint8_t bytes[3] = {1, 2, 3};
        PA_ObjectRef obj = PA_CreateObject();
        PA_Picture pic = PA_CreatePicture(bytes, 3);
        ob_set_p(obj, L"k", pic);  // ob_set_p consumes the caller's reference
        const fake::Value *v = fake::prop(obj, u"k");
        CHECK(v && v->kind == eVK_Picture && v->pic == pic);
        CHECK(v && v->pic && v->pic->bytes.size() == 3);
        PA_DisposeObject(obj);
    };

    t["control_set_scalars"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        ob_set_b(obj, L"b", true);
        ob_set_n(obj, L"n", 2.5);
        ob_set_i(obj, L"i", 7);
        ob_set_0(obj, L"z");
        const fake::Value *b = fake::prop(obj, u"b");
        const fake::Value *n = fake::prop(obj, u"n");
        const fake::Value *i = fake::prop(obj, u"i");
        CHECK(b && b->kind == eVK_Boolean && b->boolean == 1);
        CHECK(n && n->kind == eVK_Real && n->real == 2.5);
        CHECK(i && i->kind == eVK_Longint && i->longint == 7);
        PA_DisposeObject(obj);
    };

    t["control_set_object_and_collection"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        ob_set_o(obj, L"o", PA_CreateObject());          // consumes the child reference
        ob_set_c(obj, L"c", PA_CreateCollection());      // consumes the child reference
        const fake::Value *o = fake::prop(obj, u"o");
        const fake::Value *c = fake::prop(obj, u"c");
        CHECK(o && o->kind == eVK_Object && o->obj && o->obj->refs == 1);
        CHECK(c && c->kind == eVK_Collection && c->obj && c->obj->refs == 1);
        PA_DisposeObject(obj);
    };

    for (const TextCase &tc : kTextCases) {
        const TextCase *ptc = &tc;
        t[std::string("get_a_") + tc.name] = [ptc]() { runGetTextCase(*ptc); };
    }

    t["control_get_a_missing"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        CUTF8String out((const uint8_t *)"sentinel");
        CHECK(!ob_get_a(obj, L"k", &out));
        CHECK(out == CUTF8String((const uint8_t *)"sentinel"));
        PA_DisposeObject(obj);
    };

    t["control_get_a_mismatch_number"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", realValue(1));
        CUTF8String out((const uint8_t *)"sentinel");
        CHECK(ob_get_a(obj, L"k", &out));
        CHECK(out == CUTF8String((const uint8_t *)"sentinel"));
        PA_DisposeObject(obj);
    };

    t["control_get_a_get_failure"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", textValue(u"abc"));
        CUTF8String out((const uint8_t *)"sentinel");
        fake::failNextGet = true;
        ob_get_a(obj, L"k", &out);
        CHECK(!fake::failNextGet);
        CHECK(out == CUTF8String((const uint8_t *)"sentinel"));
        PA_DisposeObject(obj);
    };

    t["control_get_b_match"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", boolValue(true));
        CHECK(ob_get_b(obj, L"k"));
        PA_DisposeObject(obj);
    };

    t["get_b_mismatch_text"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", textValue(u"true"));
        CHECK(!ob_get_b(obj, L"k"));
        PA_DisposeObject(obj);
    };

    t["get_b_mismatch_object"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        PA_ObjectRef child = PA_CreateObject();
        fake::Value v;
        v.kind = eVK_Object;
        v.obj = (fake::Obj *)child;
        fake::seed(obj, u"k", v);
        PA_DisposeObject(child);
        CHECK(!ob_get_b(obj, L"k"));
        PA_DisposeObject(obj);
    };

    t["control_get_b_get_failure"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", boolValue(true));
        fake::failNextGet = true;
        CHECK(!ob_get_b(obj, L"k"));
        CHECK(!fake::failNextGet);
        PA_DisposeObject(obj);
    };

    t["control_get_n_match"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", realValue(42.5));
        CHECK(ob_get_n(obj, L"k") == 42.5);
        PA_DisposeObject(obj);
    };

    t["get_n_mismatch_text"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", textValue(u"42"));
        CHECK(ob_get_n(obj, L"k") == 0.0);
        PA_DisposeObject(obj);
    };

    t["control_get_n_get_failure"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", realValue(42.5));
        fake::failNextGet = true;
        CHECK(ob_get_n(obj, L"k") == 0.0);
        CHECK(!fake::failNextGet);
        PA_DisposeObject(obj);
    };

    t["control_get_c_match"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        PA_CollectionRef col = PA_CreateCollection();
        fake::Value v;
        v.kind = eVK_Collection;
        v.obj = (fake::Obj *)col;
        fake::seed(obj, u"k", v);
        PA_DisposeCollection(col);
        PA_CollectionRef got = ob_get_c(obj, L"k");
        CHECK(got == col);
        PA_DisposeObject(obj);
        CHECK(fake::liveObjs.count((fake::Obj *)got) == 1);  // the caller owns the returned reference
        if (got) PA_DisposeCollection(got);
    };

    t["get_c_mismatch_text"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", textValue(u"[]"));
        CHECK(ob_get_c(obj, L"k") == NULL);
        PA_DisposeObject(obj);
    };

    t["control_get_c_get_failure"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", textValue(u"[]"));
        fake::failNextGet = true;
        CHECK(ob_get_c(obj, L"k") == NULL);
        CHECK(!fake::failNextGet);
        PA_DisposeObject(obj);
    };

    t["control_is_defined"] = []() {
        PA_ObjectRef obj = PA_CreateObject();
        fake::seed(obj, u"k", realValue(1));
        CHECK(ob_is_defined(obj, L"k"));
        CHECK(!ob_is_defined(obj, L"missing"));
        PA_DisposeObject(obj);
    };

    // --- plugin commands ----------------------------------------------------

    t["command_version_info"] = []() {
        PA_ObjectRef info = (PA_ObjectRef)dispatch(1);
        CHECK(info != NULL);
        if (!info) return;
        checkText(info, u"version", u"8.0.0-synthetic");
        const fake::Value *protocols = fake::prop(info, u"protocols");
        CHECK(protocols && protocols->kind == eVK_Collection && protocols->obj);
        if (protocols && protocols->obj) {
            const char16_t *expected[] = {u"dict", u"file", u"ftp", u"ftps", u"http", u"https", u"sftp"};
            CHECK(protocols->obj->elems.size() == 7);
            for (size_t i = 0; i < protocols->obj->elems.size() && i < 7; ++i) {
                CHECK(protocols->obj->elems[i].kind == eVK_Unistring);
                CHECK(protocols->obj->elems[i].str == U(expected[i]));
            }
        }
        PA_DisposeObject(info);
    };

    t["control_command_escape"] = []() { CHECK(callText(2, u"a b/\u65E5") == U(u"a b/\u65E5")); };
    t["control_command_unescape"] = []() { CHECK(callText(3, u"a%20b") == U(u"a%20b")); };

    t["control_command_get_date"] = []() {
        PA_Unistring in = PA_CreateUnistring((PA_Unichar *)u"Sun, 06 Nov 1994 08:49:37 GMT");
        PA_Unistring out = PA_CreateUnistring((PA_Unichar *)u"");
        void *p[2] = {&in, &out};
        void *data = nullptr;
        PA_long32 result = -2;
        FourDPackex(4, p, &data, &result);
        CHECK(result == 0);
        CHECK(fake::keyOf(out) == U(u"0"));
        PA_DisposeUnistring(&in);
        PA_DisposeUnistring(&out);
    };

    t["curl_atomic_headers_certinfo"] = []() {
        HarnessScenario s;
        s.body = "hello";
        s.header = "HTTP/1.1 200 OK\r\n";
        s.certinfo = true;
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", true);
        PA_CollectionRef headers = makeCollection({textValue(u"A: 1"), realValue(5), textValue(u"B: 2"), textValue(u""),
                                                   objectValue(), textValue(u"C: \u65E5")});
        seedCollection(opts, u"HTTPHEADER", headers);
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_easy_performs() == 1);
        CHECK(harness_multi_transfers() == 0);
        CHECK(std::string(response.begin(), response.end()) == "hello");
        std::vector<std::string> expected = {"A: 1", "B: 2", u8"C: \u65E5"};
        CHECK(harness_slist_option(CURLOPT_HTTPHEADER) == expected);
        checkResult(ret, 0, 4);
        checkText(ret, u"headerInfo", u"HTTP/1.1 200 OK\r\n");
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["curl_atomic_no_certinfo"] = []() {
        HarnessScenario s;
        s.body = "x";
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", true);
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_easy_performs() == 1);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["curl_atomic_text_flag_mismatch"] = []() {
        // ATOMIC given as text: ob_get_b sees a mismatch, the transfer runs non-atomic
        HarnessScenario s;
        s.body = "x";
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", false);
        fake::seed(opts, u"ATOMIC", textValue(u"true"));
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_easy_performs() == 0);
        CHECK(harness_multi_transfers() == 1);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["curl_timeout_text_mismatch"] = []() {
        harness_set_scenario(HarnessScenario());
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", true);
        fake::seed(opts, u"TIMEOUT", textValue(u"30"));
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_long_option(CURLOPT_TIMEOUT, -1) == 0);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["curl_timeout_number"] = []() {
        harness_set_scenario(HarnessScenario());
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", true);
        fake::seed(opts, u"TIMEOUT", realValue(30));
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_long_option(CURLOPT_TIMEOUT, -1) == 30);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["curl_non_atomic_no_callback"] = []() {
        HarnessScenario s;
        s.ticks = 2;
        s.tickMs = 20;
        s.body = "x";
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"http://127.0.0.1/x", false);
        std::vector<uint8_t> response;
        PA_ObjectRef ret = runCurl(opts, u"", &response);
        CHECK(harness_multi_transfers() == 1);
        CHECK(fake::methodCalls == 0 && fake::executeMethodCalls == 0);
        CHECK(fake::delayCalls == 2);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    struct MethodCase {
        const char *name;
        fake::CallbackResult result;
    };
    static const MethodCase kMethodCases[] = {
        {"none", fake::kResultNone},
        {"bool_false", fake::kResultFalse},
        {"text", fake::kResultText},
        {"object", fake::kResultObject},
        {"failed_call", fake::kResultFail},
    };
    for (const MethodCase &mc : kMethodCases) {
        fake::CallbackResult r = mc.result;
        t[std::string("curl_callback_method_result_") + mc.name] = [r]() {
            fake::methodResult = r;
            PA_ObjectRef ret = runCallbackTransfer(u"cb_id", 2, true);
            CHECK(fake::methodCalls == 3);
            CHECK(fake::executeMethodCalls == 0);
            checkCallbackSeen(3, 4);
            checkResult(ret, 0, 4);
            PA_DisposeObject(ret);
        };
    }

    t["curl_callback_method_abort"] = []() {
        fake::methodResult = fake::kResultTrue;
        PA_ObjectRef ret = runCallbackTransfer(u"cb_id", 3, true);
        CHECK(fake::methodCalls == 1);
        checkCallbackSeen(1, 4);
        checkResult(ret, CURLE_ABORTED_BY_CALLBACK, 4);
        PA_DisposeObject(ret);
    };

    t["curl_callback_method_final_only"] = []() {
        fake::methodResult = fake::kResultFalse;
        PA_ObjectRef ret = runCallbackTransfer(u"cb_id", 0, false);
        CHECK(fake::methodCalls == 1);
        checkCallbackSeen(1, 0);
        checkResult(ret, 0, 0);
        PA_DisposeObject(ret);
    };

    t["curl_callback_execute_method"] = []() {
        PA_ObjectRef ret = runCallbackTransfer(u"cb_unknown", 2, true);
        CHECK(fake::methodCalls == 0);
        CHECK(fake::executeMethodCalls == 3);
        checkCallbackSeen(3, 4);
        checkResult(ret, 0, 4);
        PA_DisposeObject(ret);
    };

    t["curl_callback_execute_method_abort"] = []() {
        fake::executeMethodAbort = true;
        PA_ObjectRef ret = runCallbackTransfer(u"cb_unknown", 3, true);
        CHECK(fake::executeMethodCalls == 1);
        checkCallbackSeen(1, 4);
        checkResult(ret, CURLE_ABORTED_BY_CALLBACK, 4);
        PA_DisposeObject(ret);
    };

    t["ftp_dir_list"] = []() {
        HarnessScenario s;
        s.body = "drwxr-xr-x 1 owner group 0 Jan 01 2020 dir\r\n"
                 "-rw-r--r-- 1 owner group 3 Jan 01 2020 a.txt\r\n"
                 "not a listing line\r\n";
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"ftp://127.0.0.1/dir/", false);
        PA_ObjectRef ret = runFtp(7, opts, u"");
        CHECK(harness_string_option(CURLOPT_CUSTOMREQUEST) == "LIST");
        checkResult(ret, 0, 0);
        const fake::Value *list = ret ? fake::prop(ret, u"ftpparse") : nullptr;
        CHECK(list && list->kind == eVK_Collection && list->obj);
        if (list && list->obj) {
            // safeGetline yields a trailing empty line after the final CRLF (eofbit only)
            CHECK(list->obj->elems.size() == 4);
            if (list->obj->elems.size() == 4) {
                CHECK(list->obj->elems[0].kind == eVK_Object && list->obj->elems[0].obj);
                CHECK(list->obj->elems[1].kind == eVK_Object && list->obj->elems[1].obj);
                if (list->obj->elems[0].obj) checkText(list->obj->elems[0].obj, u"name", u"dir");
                if (list->obj->elems[1].obj) checkText(list->obj->elems[1].obj, u"name", u"a.txt");
                CHECK(list->obj->elems[2].kind == (char)eVK_Null);
                CHECK(list->obj->elems[3].kind == (char)eVK_Null);
            }
        }
        if (ret) PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    t["ftp_dir_list_mlsd"] = []() {
        HarnessScenario s;
        s.body = "type=dir;size=0; sub\r\n"
                 "type=file;size=3;\r\n";
        harness_set_scenario(s);
        PA_ObjectRef opts = baseOptions(u"ftp://127.0.0.1/dir/", false);
        fake::seed(opts, u"FTP_USE_MLSD", boolValue(true));
        PA_ObjectRef ret = runFtp(7, opts, u"");
        CHECK(harness_string_option(CURLOPT_CUSTOMREQUEST) == "MLSD");
        checkResult(ret, 0, 0);
        const fake::Value *list = ret ? fake::prop(ret, u"ftpparse") : nullptr;
        CHECK(list && list->kind == eVK_Collection && list->obj);
        if (list && list->obj) {
            CHECK(list->obj->elems.size() == 1);
            if (list->obj->elems.size() == 1 && list->obj->elems[0].obj) {
                checkText(list->obj->elems[0].obj, u"type", u"dir");
                checkText(list->obj->elems[0].obj, u"path", u" sub");
            }
        }
        if (ret) PA_DisposeObject(ret);
        PA_DisposeObject(opts);
    };

    return t;
}

// ---------------------------------------------------------------------------
// expected-crash probes
// ---------------------------------------------------------------------------

typedef std::map<std::string, std::function<void()> > ProbeMap;

static ProbeMap buildProbes() {
    ProbeMap p;
    p["clean_exit"] = []() {};
    p["double_dispose_string"] = []() {
        PA_Unichar s[] = {'x', 0};
        PA_Unistring u = PA_CreateUnistring(s);
        PA_Unistring alias = u;
        PA_DisposeUnistring(&u);
        PA_DisposeUnistring(&alias);
    };
    p["shallow_alias_double_clear"] = []() {
        PA_Unichar s[] = {'x', 0};
        PA_Unistring u = PA_CreateUnistring(s);
        PA_Variable v = PA_CreateVariable(eVK_Undefined);
        PA_SetStringVariable(&v, &u);  // shallow: v aliases u
        PA_ClearVariable(&v);
        PA_DisposeUnistring(&u);
    };
    p["clear_poisoned_variable"] = []() {
        PA_Variable v;
        memset(&v, 0xA5, sizeof(v));
        PA_ClearVariable(&v);
    };
    p["denied_engine_selector"] = []() { PA_RunInMainProcess(nullptr, nullptr); };
    p["denied_iconv"] = []() { harness_probe_denied_iconv(); };
    p["denied_proxy"] = []() { harness_probe_denied_proxy(); };
    return p;
}

static void initPlugin() {
    fake::methodIDs[U(u"cb_id")] = fake::kCallbackMethodID;
    PackInitBlock init;
    memset(&init, 0, sizeof(init));
    init.fCall4Dex = fake::call4d;
    void *data = nullptr;
    FourDPackex(kInitPlugin, &init, &data, nullptr);
}

static void deinitPlugin() {
    void *data = nullptr;
    FourDPackex(kDeinitPlugin, nullptr, &data, nullptr);
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        TestMap tests = buildTests();
        ProbeMap probes = buildProbes();

        if (argc == 2 && !strcmp(argv[1], "--list")) {
            for (auto &kv : tests) printf("%s\n", kv.first.c_str());
            return 0;
        }
        if (argc == 2 && !strcmp(argv[1], "--list-probes")) {
            for (auto &kv : probes) printf("%s\n", kv.first.c_str());
            return 0;
        }
        if (argc == 3 && !strcmp(argv[1], "--probe")) {
            auto it = probes.find(argv[2]);
            if (it == probes.end()) return 3;
            initPlugin();
            it->second();
            return 0;
        }
        if (argc == 3 && !strcmp(argv[1], "--test")) {
            auto it = tests.find(argv[2]);
            if (it == tests.end()) return 3;
            initPlugin();
            fake::Counts before = fake::snap();
            it->second();
            fake::Counts after = fake::snap();
            if (!(before == after)) {
                fprintf(stderr, "  live engine values changed: strings %zu->%zu objects %zu->%zu pictures %zu->%zu handles %zu->%zu\n",
                        before.strings, after.strings, before.objs, after.objs, before.pics, after.pics,
                        before.handles, after.handles);
                gOk = false;
            }
            deinitPlugin();
            printf("%s %s\n", gOk ? "PASS" : "FAIL", argv[2]);
            return gOk ? 0 : 1;
        }
        fprintf(stderr, "usage: %s --list | --list-probes | --test NAME | --probe NAME\n", argv[0]);
        return 2;
    }
}
