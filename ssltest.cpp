#include <iostream>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string>
#include <memory>
#include <string.h>
#include <thread>
#include <chrono>

template<class T> struct DeleterOf;
template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };
template<> struct DeleterOf<SSL> { void operator()(SSL *p) const { SSL_free(p); } };
template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

void shuffle(BIO* wbio_c, BIO* rbio_s, BIO* wbio_s, BIO* rbio_c) {
  char buffer[4096];
  size_t written;

  // Shuffle data between client and server:
  size_t bytesRead;
  bool didWork;
  do {
    // Read client, write to server:
    didWork = false;
    while (true) {
      int res = BIO_read_ex(wbio_c, buffer, 4096, &bytesRead); 
      if (res == 1) {  // success
        std::cout << "BIO_read_ex: successfully read " << bytesRead
            << " bytes from wbio_c." << std::endl;
        res = BIO_write_ex(rbio_s, buffer, bytesRead, &written);
        if (res == 1) {  // success
          if (written == bytesRead) {
            std::cout << "BIO_write_ex: successfully written " << written
                << " bytes to rbio_s." << std::endl;
            didWork = true;
            continue;
          }
        }
        abort();
      } else {
        if (BIO_should_retry(wbio_c)) {
          break;  // all good, just no data there
        }
        abort();
      }
    }
    // Read server, write to client:
    while (true) {
      int res = BIO_read_ex(wbio_s, buffer, 4096, &bytesRead); 
      if (res == 1) {  // success
        std::cout << "BIO_read_ex: successfully read " << bytesRead
            << " bytes from wbio_s." << std::endl;
        res = BIO_write_ex(rbio_c, buffer, bytesRead, &written);
        if (res == 1) {  // success
          if (written == bytesRead) {
            std::cout << "BIO_write_ex: successfully written " << written
                << " bytes to rbio_c." << std::endl;
            didWork = true;
            continue;
          }
        }
        abort();
      } else {
        if (BIO_should_retry(wbio_s)) {
          break;  // all good, just no data there
        }
        abort();
      }
    }
  } while (didWork);
  std::cout << "Done shuffle." << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

[[noreturn]] void print_errors_and_exit(const char *message) {
  fprintf(stderr, "%s\n", message);
  ERR_print_errors_fp(stderr);
  exit(1);
}

void verify_the_certificate(SSL *ssl) {
  int err = SSL_get_verify_result(ssl);
  if (err != X509_V_OK) {
      const char *message = X509_verify_cert_error_string(err);
      fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
      exit(1);
  }
  X509* cert = SSL_get_peer_certificate(ssl);
  if (cert == nullptr) {
      fprintf(stderr, "No certificate was presented by the server\n");
      exit(1);
  }
  X509_free(cert);
}

int main(int argc, char* argv[]) {
  // Prepare client:
  UniquePtr<SSL_CTX> ssl_ctx_c{SSL_CTX_new(TLS_method())};
  SSL_CTX_set_min_proto_version(ssl_ctx_c.get(), TLS1_2_VERSION);
  if (SSL_CTX_set_default_verify_paths(ssl_ctx_c.get()) != 1) {
    print_errors_and_exit("Error loading trust store");
  }
  if (SSL_CTX_load_verify_locations(ssl_ctx_c.get(), "certificates/ca-root.pem", nullptr) != 1) {
    print_errors_and_exit("Error loading CAfile");
  }
  SSL_CTX_use_certificate_chain_file(ssl_ctx_c.get(), "certificates/client.keyfile");
  SSL_CTX_use_PrivateKey_file(ssl_ctx_c.get(), "certificates/client-key.pem", SSL_FILETYPE_PEM);
  UniquePtr<SSL> ssl_c{SSL_new(ssl_ctx_c.get())};
  BIO* rbio_c{BIO_new(BIO_s_mem())};
  SSL_set0_rbio(ssl_c.get(), rbio_c);
  BIO* wbio_c{BIO_new(BIO_s_mem())};
  SSL_set0_wbio(ssl_c.get(), wbio_c);
  SSL_set_connect_state(ssl_c.get());
  SSL_set_tlsext_host_name(ssl_c.get(), "localhost");
  SSL_set1_host(ssl_c.get(), "localhost");

  // Prepare server:
  UniquePtr<SSL_CTX> ssl_ctx_s{SSL_CTX_new(TLS_method())};
  SSL_CTX_set_min_proto_version(ssl_ctx_s.get(), TLS1_2_VERSION);
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx_s.get(), "certificates/server.keyfile") <= 0) {
    print_errors_and_exit("Error loading server certificate");
  }
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx_s.get(), "certificates/server-key.pem", SSL_FILETYPE_PEM) <= 0) {
    print_errors_and_exit("Error loading server private key");
  }
  SSL_CTX_set_verify(ssl_ctx_s.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, nullptr);
  UniquePtr<SSL> ssl_s{SSL_new(ssl_ctx_s.get())};
  BIO* rbio_s = BIO_new(BIO_s_mem());
  SSL_set0_rbio(ssl_s.get(), rbio_s);
  BIO* wbio_s = BIO_new(BIO_s_mem());
  SSL_set0_wbio(ssl_s.get(), wbio_s);
  SSL_set_accept_state(ssl_s.get());

  int done = 0;
  int res;
  while (done != 3) {
    shuffle(wbio_c, rbio_s, wbio_s, rbio_c);
    if ((done & 1) == 0) {
      res = SSL_connect(ssl_c.get());
      if (res == 1) {
        done += 1;
      } else {
        int code = SSL_get_error(ssl_c.get(), res);
        std::cout << "SSL_connect: error: " << code << std::endl;
      }
    }
    if ((done & 2) == 0) {
      res = SSL_accept(ssl_s.get());
      if (res == 1) {
        done += 2;
      } else {
        int code = SSL_get_error(ssl_c.get(), res);
        std::cout << "SSL_accept: error: " << code << std::endl;
        ERR_print_errors_fp(stderr);
      }
    }
  }
  verify_the_certificate(ssl_c.get());

  std::string line;
  char serverbuffer[4096];
  size_t serverbufferLen = 0;
  char clientbuffer[4096];
  while (true) {
    // Get more input if all has been written:
    if (line.empty()) {
      std::cout << "What to send?" << std::endl;
      std::getline(std::cin, line);
    }
    if (line.compare("exit") == 0) {
      break;
    }

    // Write as much as possible on the client side:
    size_t written;
    int res = SSL_write_ex(ssl_c.get(), line.c_str(), line.size(), &written);
    if (res == 1) {  // success
      std::cout << "SSL_write_ex: successfully written " << written
          << " bytes on client." << std::endl;
      if (line.size() == written) {
        line.clear();
      } else {
        line = line.substr(written);
      }
    } else {
      int code = SSL_get_error(ssl_c.get(), res);
      std::cout << "SSL_write_ex: error: " << code << std::endl;
    }

    shuffle(wbio_c, rbio_s, wbio_s, rbio_c);

    // Read on the server side, append to serverbuffer:
    if (serverbufferLen < 4096) {
      size_t bytesRead;
      res = SSL_read_ex(ssl_s.get(), serverbuffer + serverbufferLen, 4096 - serverbufferLen, &bytesRead);
      if (res == 1) {   // success
        std::cout << "SSL_read_ex: successfully read " << bytesRead
            << " bytes on server." << std::endl;
        serverbufferLen += bytesRead;
      } else {
        int code = SSL_get_error(ssl_s.get(), res);
        std::cout << "SSL_read_ex: error: " << code << std::endl;
      }
    }

    shuffle(wbio_c, rbio_s, wbio_s, rbio_c);

    // Write on the server side, if there is anything to write:
    if (serverbufferLen > 0) {
      res = SSL_write_ex(ssl_s.get(), serverbuffer, serverbufferLen, &written);
      if (res == 1) {   // success
        std::cout << "SSL_write_ex: successfully wrote " << written
            << " bytes on server." << std::endl;
        if (serverbufferLen == written) {
          serverbufferLen = 0;
        } else {
          memmove(serverbuffer, serverbuffer + written, serverbufferLen - written);
          serverbufferLen -= written;
        }
      } else {
        int code = SSL_get_error(ssl_s.get(), res);
        std::cout << "SSL_write_ex: error: " << code << std::endl;
      }
    }

    shuffle(wbio_c, rbio_s, wbio_s, rbio_c);

    // And finally read on the client side:
    size_t bytesRead;
    res = SSL_read_ex(ssl_c.get(), clientbuffer, 4096, &bytesRead);
    if (res == 1) {  // success
      std::cout << "SSL_read_ex: successfully read " << bytesRead
          << " bytes on client." << std::endl;
      std::cout << "Read on client over connection:\n"
          << std::string(clientbuffer, bytesRead) << std::endl;
    } else {
      int code = SSL_get_error(ssl_c.get(), res);
      std::cout << "SSL_read_ex: error: " << code << std::endl;
    }

  }
}
