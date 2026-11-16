/* APKBridge runtime :: C ABI for the iOS/Swift host.
 * Pure C signatures so Swift imports this via a bridging header and calls the
 * C++ interpreter/importer without C++ interop. Every returned string is
 * newly-allocated JSON; free it with apkbridge_free(). */
#ifndef APKBRIDGE_RUNTIME_H
#define APKBRIDGE_RUNTIME_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Import an APK: validate the ZIP, parse AndroidManifest.xml, enumerate DEX and
 * native libraries, and safely extract classes*.dex + AndroidManifest.xml into
 * destDir (path-traversal / size / zip-bomb protected). Returns JSON:
 * {"ok":true,"package":"...","versionName":"...","versionCode":N,
 *  "minSdk":N,"targetSdk":N,"permissions":[...],
 *  "dexFiles":[{"name":"classes.dex","path":"<destDir>/classes.dex"}...],
 *  "nativeLibs":[{"abi":"arm64-v8a","name":"libfoo.so"}...]}
 * or {"ok":false,"error":"..."}. Caller frees with apkbridge_free(). */
const char* apkbridge_import_apk(const char* apkPath, const char* destDir);

/* List classes in a DEX (paginated). Returns JSON:
 * {"total":N,"offset":O,"classes":["La/b/C;",...]}. */
const char* apkbridge_list_classes(const char* dexPath, int offset, int limit);

/* List methods of one class. Returns JSON:
 * {"class":"La/b/C;","methods":[{"name":"m","shorty":"II","static":true,
 *   "hasCode":true,"runnable":true}...]}
 * "runnable" marks a static method with no-arg or int-only params and code —
 * i.e. one the current interpreter subset can attempt. */
const char* apkbridge_list_methods(const char* dexPath, const char* className);

/* Run <cls>-><method>(<shorty>) with integer args. Returns JSON:
 * {"kind":"int|ref|void|exception|unsupported|error","value":"...","extra":"..."} */
const char* apkbridge_run_method(const char* dexPath, const char* cls,
                                 const char* method, const char* shorty,
                                 const int32_t* args, int nargs);

/* Like apkbridge_run_method but with an explicit mode ("analysis"|"functional")
 * and an execution trace: adds "mode" and "trace":{entries[],logcat[]}. */
const char* apkbridge_run_method_mode(const char* dexPath, const char* cls,
                                      const char* method, const char* shorty,
                                      const int32_t* args, int nargs, const char* mode);

/* Model framework instantiation + initial lifecycle for an Application
 * subclass: alloc instance, run <init> then onCreate(this). */
const char* apkbridge_run_lifecycle(const char* dexPath, const char* appClass,
                                    const char* mode);

/* Crash-safe install: prepare+commit a validated staging code dir into the app
 * sandbox (keeps a backup until verified). Returns {"ok":bool,"state":"...","error":"..."}. */
const char* apkbridge_install_commit(const char* sandboxDir, const char* stagingDexDir);
/* Recover an interrupted install on launch. Returns {"ok":bool,"state":"...","note":"..."}. */
const char* apkbridge_install_recover(const char* sandboxDir);

/* DEX summary: {"classes":N,"methods":N,"strings":N}. */
const char* apkbridge_inspect_dex(const char* dexPath);

void apkbridge_free(const char* s);

#ifdef __cplusplus
}
#endif
#endif /* APKBRIDGE_RUNTIME_H */
