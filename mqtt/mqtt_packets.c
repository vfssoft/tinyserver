#include "mqtt_packets.h"

static const char* tm__pkt_name(int pkt_type) {
  switch (pkt_type) {
    case PKT_TYPE_CONNECT: return "CONNECT";
    case PKT_TYPE_CONNACK: return "CONNACK";
    case PKT_TYPE_PUBLISH: return "PUBLISH";
    case PKT_TYPE_PUBACK: return "PUBACK";
    case PKT_TYPE_PUBREC: return "PUBREC";
    case PKT_TYPE_PUBREL: return "PUBREL";
    case PKT_TYPE_PUBCOMP: return "PUBCOMP";
    case PKT_TYPE_SUBSCRIBE: return "SUBSCRIBE";
    case PKT_TYPE_SUBACK: return "SUBACK";
    case PKT_TYPE_UNSUBSCRIBE: return "UNSUBSCRIBE";
    case PKT_TYPE_UNSUBACK: return "UNSUBACK";
    case PKT_TYPE_PINGREQ: return "PINGREQ";
    case PKT_TYPE_PINGRESP: return "PINGRESP";
    case PKT_TYPE_DISCONNECT: return "DISCONNECT";
    default: return "UNKNOWN PACKET";
  }
}

BOOL tm__parse_packet(
    const char* data,
    int data_len,
    int* pkt_bytes_cnt,
    unsigned int* remaining_length,
    ts_error_t* error
)
{
  int offset = 0;
  int pkt_type;
  int flags;
  unsigned long long multiplier = 1;

  if (data_len < 2) {
    return FALSE;
  }
  
  pkt_type = (data[0] & 0xF0) >> 4;
  flags = (data[0] & 0x0F);
  
  // validate the flags
  switch (pkt_type) {
    case PKT_TYPE_CONNECT:
    case PKT_TYPE_CONNACK:
    case PKT_TYPE_PUBACK:
    case PKT_TYPE_PUBREC:
    case PKT_TYPE_PUBCOMP:
    case PKT_TYPE_SUBACK:
    case PKT_TYPE_UNSUBACK:
    case PKT_TYPE_PINGREQ:
    case PKT_TYPE_PINGRESP:
    case PKT_TYPE_DISCONNECT:
      if (flags != 0) {
        ts_error__set_msgf(
            error,
            TS_ERR_MALFORMED_MQTT_PACKET,
            "Invalid Reserved flags in the incoming %s packet",
            tm__pkt_name(pkt_type)
        );
        return FALSE;
      }
      break;
      
    case PKT_TYPE_PUBLISH: // The flags have special meanings, parsing it out side of this function
      break;
    
    case PKT_TYPE_PUBREL:
    case PKT_TYPE_SUBSCRIBE:
    case PKT_TYPE_UNSUBSCRIBE:
      if (flags != 0x02) {
        ts_error__set_msgf(
            error,
            TS_ERR_MALFORMED_MQTT_PACKET,
            "Invalid Reserved flags in the incoming %s packet",
            tm__pkt_name(pkt_type)
        );
        return FALSE;
      }
      break;
      
    default:
      ts_error__set_msgf(error, TS_ERR_MALFORMED_MQTT_PACKET, "Invalid Control Packet Type(%d)", pkt_type);
      return FALSE;
  }
  
  *remaining_length = 0;
  offset = 1;
  while (TRUE) {
    *remaining_length += ((data[offset] & 0x7F) * multiplier);
    multiplier *= 128;
  
    if (multiplier > 128*128*128) {
      // The incoming packet encodes the variable length in more than 4 bytes
      ts_error__set_msg(error, TS_ERR_MALFORMED_MQTT_PACKET, "Variable length is too large(0xFFFFFF7F)");
      return FALSE;
    }
    
    if ((data[offset] & 0x80) != 0x80) {
      break; // parse remaining length successfully
    }
    
    offset++;
    
    if (offset >= data_len) {
      return FALSE; // we want more data, but no
    }
    
  }
  
  *pkt_bytes_cnt = offset + *remaining_length;
  
  return *pkt_bytes_cnt <= data_len;
}


int tm_packet_decoder__set(tm_packet_decoder_t* decoder, const char* buf, int len) {
  decoder->buf = buf;
  decoder->len = len;
  decoder->offset = 0;
  return 0;
}
int tm_packet_decoder__available(tm_packet_decoder_t* decoder){
  return decoder->len - decoder->offset;
}
const char* tm_packet_decoder__ptr(tm_packet_decoder_t* decoder) {
  return decoder->buf + decoder->offset;
}
static int tm_packet_decoder__check_available(tm_packet_decoder_t* decoder, int len) {
  int avail = tm_packet_decoder__available(decoder);
  if (avail < len) {
    return TS_ERR_INVALID_OPERATION;
  }
  return 0;
}
int tm_packet_decoder__read_byte(tm_packet_decoder_t* decoder, int* ret) {
  int err;

  err = tm_packet_decoder__check_available(decoder, 1);
  if (err) return err;

  *ret = tm_packet_decoder__ptr(decoder)[0] & 0xFF;
  decoder->offset += 1;
  return 0;
}
int tm_packet_decoder__read_int16(tm_packet_decoder_t* decoder, int* ret) {
  int err;

  err = tm_packet_decoder__check_available(decoder, 2);
  if (err) return err;

  *ret = bytes2uint16_be(tm_packet_decoder__ptr(decoder));
  decoder->offset += 2;
  return 0;
}
int tm_packet_decoder__read_int16_string(tm_packet_decoder_t* decoder, int* retlen, const char** retstr) {
  int err;

  err = tm_packet_decoder__read_int16(decoder, retlen);
  if (err) return err;

  err = tm_packet_decoder__check_available(decoder, *retlen);
  if (err) return err;

  *retstr = tm_packet_decoder__ptr(decoder);
  return 0;
}




