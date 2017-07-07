#include "util/init.h"

#include <event2/thread.h>
#include <evhtp.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <string>

#include "config.h"
#include "log/ct_extensions.h"
#include "proto/cert_serializer.h"
#include "version.h"

using std::string;

namespace util {


namespace {


void LibEventLog(int severity, const char* msg) {
  const string msg_s(msg);
  switch (severity) {
    case EVENT_LOG_DEBUG:
      VLOG(1) << msg_s;
      break;
    case EVENT_LOG_MSG:
      LOG(INFO) << msg_s;
      break;
    case EVENT_LOG_WARN:
      LOG(WARNING) << msg_s;
      break;
    case EVENT_LOG_ERR:
      LOG(ERROR) << msg_s;
      break;
    default:
      LOG(ERROR) << "LibEvent(?): " << msg_s;
      break;
  }
}


}  // namespace


void InitCT(int* argc, char** argv[]) {
  google::SetVersionString(cert_trans::kBuildVersion);
  google::ParseCommandLineFlags(argc, argv, true);
  google::InitGoogleLogging(*argv[0]);
  google::InstallFailureSignalHandler();

  event_set_log_callback(&LibEventLog);

  evthread_use_pthreads();
  // Set-up OpenSSL for multithreaded use:
  evhtp_ssl_use_threads();

  // Explicitly enable FIPS for OpenSSL:
  int mode = FIPS_mode(), ret = 0; unsigned long err = 0;
  if(mode == 0) {
    ret = FIPS_mode_set(1 /*on*/);
    if(ret != 1) {
      err = ERR_get_error();
    }
  }
  if(ret != 1) {
    ERR_load_crypto_strings();
    LOG(WARNING) << "Failed to set FIPS validated mode of operation: " << ERR_error_string(err, NULL);
    LOG(WARNING) << "OpenSSL Version: " << SSLeay_version(SSLEAY_VERSION);
    LOG(WARNING) << "OpenSSL CFlags: " << SSLeay_version(SSLEAY_CFLAGS);
    LOG(WARNING) << "OpenSSL BuiltOn: " << SSLeay_version(SSLEAY_BUILT_ON);
    LOG(WARNING) << "OpenSSL Platform: " << SSLeay_version(SSLEAY_PLATFORM);
    LOG(WARNING) << "OpenSSL Dir: " << SSLeay_version(SSLEAY_DIR);
    ERR_free_strings();
  } else {
    LOG(INFO) << "OpenSSL operating in FIPS validated mode of operation.";
  }

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();

  cert_trans::LoadCtExtensions();

  LOG(INFO) << "Build version: " << google::VersionString();
#ifdef ENABLE_HARDENING
  LOG(INFO) << "Binary built with hardening enabled.";
#else
  LOG(WARNING) << "Binary built with hardening DISABLED.";
#endif
}


}  // namespace util
