
#include "testutil.h"
#include "tinyunit.h"

#ifdef WIN32
#include <windows.h>
#include <Psapi.h>
#include <sysinfoapi.h>
#else
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#endif


const char* cur_dir() {
  char* file = strdup(__FILE__);
  int idx = strlen(file) - 1;
  while (file[idx] != '\\') idx--;
  file[idx] = 0;
  return file;
}


ts_t* start_server(int proto) {
  ts_t* server = ts_server__create();
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "127.0.0.1", 12345);
  ts_server__set_listener_protocol(server, 0, proto);

  if (ts_use_ssl(proto)) {
    const char* dir_path = cur_dir();
    char crtpath[1024];
    char keypath[1024];

    sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
    sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);

    ts_server__set_listener_certs(server, 0, crtpath, keypath);
  }

  return server;
}

tm_t* start_mqtt_server(int proto, tm_callbacks_t* cbs) {
  return start_mqtt_server_custom_port(proto, -1, cbs);
}
tm_t* start_mqtt_server_custom_port(int proto, int listen_port, tm_callbacks_t* cbs) {
  const char* dir_path = cur_dir();
  char crtpath[1024];
  char keypath[1024];
  
  sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
  sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);
  
  tm_t* tm = tm__create();
  tm__set_listener_count(tm, 1);
  tm__set_listener_protocol(tm, 0, proto);
  
  switch (proto) {
    case TS_PROTO_TCP:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_PLAIN_PORT: listen_port);
      break;
    case TS_PROTO_TLS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_TLS_PORT: listen_port);
      tm__set_listener_certs(tm, 0, crtpath, keypath);
      break;
    case TS_PROTO_WS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_WS_PORT: listen_port);
      break;
    case TS_PROTO_WSS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_WSS_PORT: listen_port);
      tm__set_listener_certs(tm, 0, crtpath, keypath);
      break;
    default:
      assert(0);
  }
  
  tm__set_callbacks(tm, cbs);
  
  return tm;
}


void assert_bytes_equals(const char* d1, int d1len, const char* d2, int d2len) {
  ASSERT_EQ(d1len, d2len);

  for (int i = 0; i < d1len; i++) {
    ASSERT_EQ(d1[i], d2[i]);
  }
}


static unsigned char hex_char_to_byte(char high, char low) {
  unsigned char byte = 0;
  
  // Convert high nibble
  if (high >= '0' && high <= '9') {
    byte |= (high - '0') << 4;
  } else if (high >= 'a' && high <= 'f') {
    byte |= (high - 'a' + 10) << 4;
  } else if (high >= 'A' && high <= 'F') {
    byte |= (high - 'A' + 10) << 4;
  }
  
  // Convert low nibble
  if (low >= '0' && low <= '9') {
    byte |= (low - '0');
  } else if (low >= 'a' && low <= 'f') {
    byte |= (low - 'a' + 10);
  } else if (low >= 'A' && low <= 'F') {
    byte |= (low - 'A' + 10);
  }
  
  return byte;
}
void decode_hex(const char* hex, unsigned char* bytes) {
  int len = strlen(hex);
  int out_len = len / 2;
  for (size_t i = 0; i < out_len; i++) {
    bytes[i] = hex_char_to_byte(hex[2 * i], hex[2 * i + 1]);
  }
}

long long get_current_time_millis() {
#ifdef _WIN32
  FILETIME ft;
  LARGE_INTEGER li;
  
  GetSystemTimePreciseAsFileTime(&ft);
  
  li.LowPart = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  
  return (long long)(li.QuadPart / 10000LL - 11644473600000LL);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

long get_current_process_memory_usage() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS_EX pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
    return pmc.PrivateUsage;
  } else {
    return -1;
  }
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == 0) {
      return ru.ru_maxrss * 1024; // Convert kilobytes to bytes
  } else {
      return -1;
  }
#endif
}

void wait(int milliseconds) {
  unsigned long long end_time_marker = get_current_time_millis() + milliseconds;
  while (get_current_time_millis() < end_time_marker) {
    mysleep(20);
  }
}
void mysleep(int milliseconds) {
#ifdef _WIN32
  Sleep(milliseconds);
#else
  usleep(milliseconds);
#endif
}

static int encode_short(char* buf, int val) {
  buf[0] = (char)((val & 0xFF00) >> 8);
  buf[1] = (char)(val & 0x00FF);
  return 2;
}
static int encode_utf8_string(char* buf, const char* data, int len) {
  encode_short(buf, len);
  memcpy(buf + 2, data, len);
  return len + 2;
}

int build_connect_pkt(char* buf,
    const char* client_id,
    int clean_session,
    const char* username, const char* password,
    const char* will_msg, int will_msg_len, const char* will_topic, int will_qos, int will_retain,
    int keep_alive
) {
  int client_id_len = client_id == NULL ? 0 : strlen(client_id);
  int username_len = username == NULL ? 0 : strlen(username);
  int password_len = password == NULL ? 0 : strlen(password);
  int will_topic_len = will_topic == NULL ? 0 : strlen(will_topic);
  
  int variable_header_offset = 0;
  int offset;
  
  buf[0] = 0x10; // type and reserved bits
  
  // estimate how long needed to encode remaining length
  if (client_id_len + username_len + password_len + will_topic_len + 10 > 127) {
    // use two bytes to encode the length
    variable_header_offset = 3;
  } else {
    // use one byte to encode the length
    variable_header_offset = 2;
  }
  
  offset = variable_header_offset;
  offset += encode_utf8_string(buf + offset, "MQTT", 4);
  
  buf[offset] = 0x04; // Version
  offset++;
  
  int flags = clean_session << 1;
  if (will_msg != NULL) {
    flags |= 1 << 2; // will flag
    flags |= will_qos << 3;
    flags |= will_retain << 5;
  }
  if (username != NULL) {
    flags |= 1 << 6;
  }
  if (password != NULL) {
    flags |= 1 << 7;
  }
  
  buf[offset] = flags;
  offset++;
  
  buf[offset] = keep_alive & 0xFF00 >> 8;
  buf[offset+1] = keep_alive & 0x00FF;
  offset += 2;
  
  offset += encode_utf8_string(buf + offset, client_id, client_id_len);
  
  if (will_msg) {
    offset += encode_utf8_string(buf + offset, will_topic, strlen(will_topic));
    offset += encode_utf8_string(buf + offset, will_msg, will_msg_len);
  }
  if (username) {
    offset += encode_utf8_string(buf + offset, username, strlen(username));
  }
  if (password) {
    offset += encode_utf8_string(buf + offset, password, strlen(password));
  }
  
  int remaining_len = offset - variable_header_offset;
  if (remaining_len <= 127) {
    assert(variable_header_offset == 2);
    buf[1] = remaining_len;
  } else {
    assert(variable_header_offset == 3);
    buf[1] = (remaining_len / 128) | 0x80;
    buf[2] = remaining_len % 128;
  }
  
  return offset;
}

int build_subscribe_pkt(char* buf, int pkt_id, const char* topic, int qos) {
  buf[0] = 0x82;
  //buf[1] = 0;
  
  int offset = 2;
  offset += encode_short(buf + offset, pkt_id);
  
  offset += encode_utf8_string(buf + offset, topic, strlen(topic));
  
  buf[offset] = qos;
  offset++;
  
  buf[1] = offset - 2;
  
  return offset;
}

int build_publish_pkt(
    char* buf,
    const char* topic,
    int pkt_id,
    int qos, int dup, int retain,
    const char* payload, int payload_len
) {
  buf[0] = 0x30;
  if (dup) buf[0] |= 0x08;
  if (qos > 0) buf[0] |= (char)(qos << 1);
  if (retain) buf[0] |= 0x01;

  int offset = 0;
  int variable_header_offset = 0;

  if (2 + strlen(topic) + 2 + payload_len > 127) {
    // use two bytes to encode the length
    variable_header_offset = 3;
  } else {
    // use one byte to encode the length
    variable_header_offset = 2;
  }
  offset = variable_header_offset;

  offset += encode_utf8_string(buf + offset, topic, strlen(topic));

  offset += encode_short(buf + offset, pkt_id);

  memcpy(buf + offset, payload, payload_len);
  offset += payload_len;


  int remaining_len = offset - variable_header_offset;
  if (remaining_len <= 127) {
    assert(variable_header_offset == 2);
    buf[1] = remaining_len;
  } else {
    assert(variable_header_offset == 3);
    buf[1] = (remaining_len / 128) | 0x80;
    buf[2] = remaining_len % 128;
  }

  return offset;
}

int assert_msg(msg_t* m, const char* topic, const char* payload, int payload_len, int qos, int retained) {
  ASSERT_STR_EQ(m->topic, topic);
  ASSERT_EQ(m->qos, qos);
  if (payload_len >= 0) {
    ASSERT_EQ(m->payload_len, payload_len);
    if (payload_len > 0) {
      ASSERT_MEM_EQ(payload, (char*)m->payload, m->payload_len);
    }
  }
  ASSERT_EQ(m->retained, retained);
}
