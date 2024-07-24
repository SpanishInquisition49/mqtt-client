#include "connack.h"

char *connack_reason_code_to_string(connack_reason_code_t reason_code) {
  switch (reason_code) {
  case CONNACK_SUCCESS:
    return "Success";
  case CONNACK_UNSPECIFIED_ERROR:
    return "Unspecified error";
  case CONNACK_MALFORMED_PACKET:
    return "Malformed packet";
  case CONNACK_PROTOCOL_ERROR:
    return "Protocol error";
  case CONNACK_IMPLEMENTATION_SPECIFIC_ERROR:
    return "Implementation specific error";
  case CONNACK_UNSUPPORTED_PROTOCOL_VERSION:
    return "Unsupported protocol version";
  case CONNACK_CLIENT_IDENTIFIER_NOT_VALID:
    return "Client identifier not valid";
  case CONNACK_BAD_USER_NAME_OR_PASSWORD:
    return "Bad user name or password";
  case CONNACK_NOT_AUTHORIZED:
    return "Not authorized";
  case CONNACK_SERVER_UNAVAILABLE:
    return "Server unavailable";
  case CONNACK_SERVER_BUSY:
    return "Server busy";
  case CONNACK_BANNED:
    return "Banned";
  case CONNACK_SERVER_SHUTTING_DOWN:
    return "Server shutting down";
  case CONNACK_BAD_AUTHENTICATION_METHOD:
    return "Bad authentication method";
  case CONNACK_TOPIC_NAME_INVALID:
    return "Topic name invalid";
  case CONNACK_PACKET_TOO_LARGE:
    return "Packet too large";
  case CONNACK_QUOTA_EXCEEDED:
    return "Quota exceeded";
  case CONNACK_PAYLOAD_FORMAT_INVALID:
    return "Payload format invalid";
  case CONNACK_RETAIN_NOT_SUPPORTED:
    return "Retain not supported";
  case CONNACK_QOS_NOT_SUPPORTED:
    return "QoS not supported";
  case CONNACK_USE_ANOTHER_SERVER:
    return "Use another server";
  case CONNACK_SERVER_MOVED:
    return "Server moved";
  case CONNAK_CONNECTION_RATE_EXCEEDED:
    return "Connection rate exceeded";
  default:
    return "Unknown reason code";
  }
}
