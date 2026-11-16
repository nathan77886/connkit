/* Private, headless FreeRDP worker. Credentials enter only through stdin.
 * stdout is a bounded binary IPC channel; no target data is logged. */
#include <arpa/inet.h>
#include <errno.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
#include <freerdp/settings.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <png.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>

static char *pin;
static int relay_port;
/* This exported socket boundary also covers server-directed redirection inside
 * FreeRDP. The worker may connect only to the route-owned loopback relay. */
int connect(int fd, const struct sockaddr *address, socklen_t n) {
  if (!address || n < sizeof(struct sockaddr_in) ||
      address->sa_family != AF_INET) {
    errno = EACCES;
    return -1;
  }
  const struct sockaddr_in *a = (const struct sockaddr_in *)address;
  if (a->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
      ntohs(a->sin_port) != relay_port) {
    errno = EACCES;
    return -1;
  }
  return (int)syscall(SYS_connect, fd, address, n);
}
static int cert_ok, painted, desktop;
static void reply(int status, const void *p, size_t n) {
  unsigned char s = status;
  uint32_t len = htonl((uint32_t)n);
  if (fwrite(&s, 1, 1, stdout) != 1 || fwrite(&len, 4, 1, stdout) != 1 ||
      fwrite(p, 1, n, stdout) != n || fflush(stdout))
    exit(1);
}
static char *field(void) {
  uint32_t n;
  if (fread(&n, 4, 1, stdin) != 1)
    exit(1);
  n = ntohl(n);
  if (n > 65536)
    exit(1);
  char *p = calloc(n + 1, 1);
  if (!p || fread(p, 1, n, stdin) != n)
    exit(1);
  return p;
}
static int verify(freerdp *i, const BYTE *data, size_t n, const char *host,
                  UINT16 port, DWORD flags) {
  (void)i;
  (void)host;
  (void)port;
  (void)flags;
  BIO *b = BIO_new_mem_buf(data, (int)n);
  X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
  unsigned char digest[32];
  unsigned int len = 0;
  char hex[65];
  int ok = x && X509_digest(x, EVP_sha256(), digest, &len) && len == 32;
  if (ok) {
    for (int k = 0; k < 32; k++)
      snprintf(hex + 2 * k, 3, "%02x", digest[k]);
    ok = strlen(pin) == 64 && CRYPTO_memcmp(hex, pin, 64) == 0;
  }
  X509_free(x);
  BIO_free(b);
  cert_ok = ok;
  return ok ? 2 : 0;
}
static BOOL end_paint(rdpContext *ctx) {
  (void)ctx;
  painted = 1;
  return TRUE;
}
static BOOL resize(rdpContext *ctx) {
  UINT32 w = freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopWidth),
         h = freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopHeight);
  if (w > 1280 || h > 1024 || w < 200 || h < 200)
    return FALSE;
  return gdi_resize(ctx->gdi, w, h);
}
static BOOL post_connect(freerdp *i) {
  UINT32 w = freerdp_settings_get_uint32(i->settings, FreeRDP_DesktopWidth),
         h = freerdp_settings_get_uint32(i->settings, FreeRDP_DesktopHeight);
  if (w > 1280 || h > 1024 || w < 200 || h < 200 || !cert_ok ||
      !gdi_init(i, PIXEL_FORMAT_BGRA32))
    return FALSE;
  i->update->EndPaint = end_paint;
  i->update->DesktopResize = resize;
  desktop = 1;
  return TRUE;
}
static void screenshot(freerdp *i) {
  rdpGdi *g = i->context->gdi;
  if (!desktop || !painted || !g || !g->primary_buffer) {
    reply(1, "no desktop frame received yet", 29);
    return;
  }
  png_image im;
  memset(&im, 0, sizeof(im));
  im.version = PNG_IMAGE_VERSION;
  im.width = g->width;
  im.height = g->height;
  im.format = PNG_FORMAT_BGRA;
  png_alloc_size_t n = 0;
  if (!png_image_write_to_memory(&im, NULL, &n, 0, g->primary_buffer, g->stride,
                                 NULL) ||
      n > 700000) {
    reply(1, "screenshot exceeds limit", 24);
    return;
  }
  void *p = malloc(n);
  if (!p) {
    reply(1, "screenshot allocation failed", 28);
    return;
  }
  if (png_image_write_to_memory(&im, p, &n, 0, g->primary_buffer, g->stride,
                                NULL))
    reply(0, p, n);
  else
    reply(1, "screenshot encoding failed", 26);
  free(p);
  png_image_free(&im);
}
int main(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  WLog_SetLogLevel(WLog_GetRoot(), WLOG_OFF);
  char *port = field(), *user = field(), *password = field(), *domain = field();
  pin = field();
  char *width = field(), *height = field(), *mode = field();
  relay_port = atoi(port);
  freerdp *i = freerdp_new();
  if (!i || !freerdp_context_new(i))
    return 1;
  rdpSettings *s = i->settings;
  freerdp_settings_set_string(s, FreeRDP_ServerHostname, "127.0.0.1");
  freerdp_settings_set_uint32(s, FreeRDP_ServerPort, atoi(port));
  freerdp_settings_set_string(s, FreeRDP_Username, user);
  freerdp_settings_set_string(s, FreeRDP_Password, password);
  freerdp_settings_set_string(s, FreeRDP_Domain, domain);
  freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth, atoi(width));
  freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, atoi(height));
  freerdp_settings_set_uint32(s, FreeRDP_ColorDepth, 32);
  freerdp_settings_set_bool(s, FreeRDP_ExternalCertificateManagement, TRUE);
  freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, TRUE);
  freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_RdpSecurity, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_AuthenticationOnly,
                            strcmp(mode, "auth") == 0);
  freerdp_settings_set_bool(s, FreeRDP_AutoReconnectionEnabled, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_GatewayEnabled, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_SupportGraphicsPipeline, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_RedirectClipboard, FALSE);
  freerdp_settings_set_bool(s, FreeRDP_RedirectDrives, FALSE);
  i->VerifyX509Certificate = verify;
  i->PostConnect = post_connect;
  OPENSSL_cleanse(password, strlen(password));
  free(password);
  free(port);
  free(user);
  free(domain);
  free(width);
  free(height);
  BOOL connected = freerdp_connect(i);
  if (!connected || !cert_ok) {
    char msg[96];
    snprintf(msg, sizeof(msg), "%s (FreeRDP 0x%08x)",
             cert_ok ? "NLA authentication/connection failed"
                     : "certificate verification or negotiation failed",
             freerdp_get_last_error(i->context));
    reply(1, msg, strlen(msg));
  } else if (strcmp(mode, "auth") == 0) {
    reply(0, "authenticated", 13);
  } else if (desktop) {
    reply(0, "desktop", 7);
    while (!freerdp_shall_disconnect(i)) {
      HANDLE handles[64];
      DWORD count = freerdp_get_event_handles(i->context, handles, 64);
      if (!count)
        break;
      if (WaitForMultipleObjects(count, handles, FALSE, 25) == WAIT_FAILED ||
          !freerdp_check_event_handles(i->context))
        break;
      struct pollfd fd = {STDIN_FILENO, POLLIN, 0};
      if (poll(&fd, 1, 0) > 0) {
        char line[128];
        if (!fgets(line, sizeof(line), stdin))
          break;
        unsigned int x, y, flags, code, down;
        if (strcmp(line, "shot\n") == 0)
          screenshot(i);
        else if (sscanf(line, "mouse %u %u %u", &x, &y, &flags) == 3 &&
                 x < (unsigned)i->context->gdi->width &&
                 y < (unsigned)i->context->gdi->height && flags <= 65535) {
          BOOL ok = freerdp_input_send_mouse_event(i->input, flags, x, y);
          reply(ok ? 0 : 1, "input", 5);
        } else if (sscanf(line, "key %u %u", &code, &down) == 2 &&
                   code <= 511 && down <= 1) {
          BOOL ok = freerdp_input_send_keyboard_event_ex(i->input, down, code);
          reply(ok ? 0 : 1, "input", 5);
        } else if (strcmp(line, "close\n") == 0)
          break;
        else
          reply(1, "invalid command", 15);
      }
    }
  } else
    reply(1, "desktop activation failed", 25);
  freerdp_disconnect(i);
  if (i->context->gdi)
    gdi_free(i);
  freerdp_context_free(i);
  freerdp_free(i);
  free(pin);
  free(mode);
  return connected ? 0 : 1;
}
