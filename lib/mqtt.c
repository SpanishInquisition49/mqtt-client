#include "mqtt.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PORT_STR_LEN 5

/**
 * MQTT string.
 */
typedef struct {
  unsigned char msb;
  unsigned char lsb;
  char *data;
} mqtt_string_t;

/**
 * MQTT CONNECT packet.
 * https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901033
 */
typedef struct {
  unsigned char fixed_header;
  mqtt_string_t protocol_name;
  unsigned char protocol_version;
  unsigned char connect_flags;
  unsigned short keep_alive;
  // connect properties
  unsigned char session_expiry_interval;
  unsigned char receive_maximum;
  unsigned short maximum_packet_size;
  unsigned short topic_alias_maximum;
  unsigned char request_response_information;
  unsigned char request_problem_information;
  unsigned char user_properties;
  unsigned char authentication_method;
  unsigned char authentication_data;
  mqtt_string_t client_id;
  mqtt_string_t will_topic;
  mqtt_string_t will_message;
  mqtt_string_t username;
  mqtt_string_t password;
} mqtt_connect_packet_t;

/**
 * Convert a character array to a MQTT string.
 *
 * @param data The character array
 * @return The MQTT string
 */
mqtt_string_t char_to_mqtt_string(char *data);

/**
 * Create a new MQTT CONNECT packet.
 *
 * @param client The MQTT client
 * @return The MQTT CONNECT packet
 */
mqtt_connect_packet_t mqtt_create_connect_packet(mqtt_client_t *client);

/**
 * Print the MQTT packet.
 *
 * @param packet The packet
 * @param length The length of the packet
 */
void mqtt_print_packet(unsigned char *packet, int length) {
  for (int i = 0; i < length; i++) {
    printf("%02X ", packet[i]);
  }
  printf("\n");
}

unsigned char mqtt_short_to_msb(unsigned short value) { return value >> 8; }
unsigned char mqtt_short_to_lsb(unsigned short value) { return value & 0xFF; }

mqtt_client_t *mqtt_client_create(char *host, int port, char *client_id,
                                  char *username, char *password,
                                  unsigned char qos, unsigned char retain,
                                  unsigned char clean_session,
                                  unsigned short keep_alive, char *will_topic,
                                  char *will_message, unsigned char will_qos,
                                  unsigned char will_retain) {
  mqtt_client_t *client = calloc(1, sizeof(mqtt_client_t));
  if (client == NULL)
    return NULL;
  client->host = host == NULL ? NULL : strdup(host);
  client->port = port;
  client->client_id = client_id == NULL ? NULL : strdup(client_id);
  client->username = username == NULL ? NULL : strdup(username);
  client->password = password == NULL ? NULL : strdup(password);
  client->qos = qos;
  client->retain = retain;
  client->clean_session = clean_session;
  client->keep_alive = keep_alive;
  client->will_topic = will_topic == NULL ? NULL : strdup(will_topic);
  client->will_message = will_message == NULL ? NULL : strdup(will_message);
  client->will_qos = will_qos;
  client->will_retain = will_retain;
  return client;
}

void mqtt_client_destroy(mqtt_client_t *client) {
  if (client == NULL)
    return;
  if (client->host != NULL)
    free(client->host);
  if (client->client_id != NULL)
    free(client->client_id);
  if (client->username != NULL)
    free(client->username);
  if (client->password != NULL)
    free(client->password);
  if (client->will_topic != NULL)
    free(client->will_topic);
  if (client->will_message != NULL)
    free(client->will_message);
  free(client);
  return;
}

mqtt_reason_code_t mqtt_client_connect(mqtt_client_t *client) {
  // connection guard
  if (client->host == NULL)
    return MQTT_ERROR;
  if (client->port == 0)
    return MQTT_ERROR;
  if (client->client_id == NULL)
    return MQTT_ERROR;
  if (client->keep_alive == 0)
    return MQTT_ERROR;

  int sfd, s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = 0;
  char port_str[MAX_PORT_STR_LEN];
  snprintf(port_str, MAX_PORT_STR_LEN, "%d", client->port);
  s = getaddrinfo(client->host, port_str, &hints, &result);
  if (s != 0) {
    return MQTT_ERROR;
  }

  // getaddrinfo() returns a list of address structures.
  // Try each address until we successfully connect(2).
  // If socket(2) (or connect(2)) fails, we (close the socket
  // and try the next address.

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;
    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break; // success
    close(sfd);
  }
  freeaddrinfo(result);

  if (rp == NULL) {
    return MQTT_ERROR;
  }
  client->socket = sfd;

  // Create the CONNECT packet
  mqtt_connect_packet_t connect_packet = mqtt_create_connect_packet(client);
  // Send the CONNECT packet with a single write system call, check if optional
  // fields are present like will, username, and pssword
  
  // Calculate the length of the CONNECT packet
  int packet_length = 2 + 2 + 4 + 1 + 1 + 2; // Fixed header + Protocol name +
                                              // Protocol version + Connect flags + Keep alive
  // Connect properties length
  packet_length += 1;
  packet_length += 2 + strlen(client->client_id); // Client ID
  // Will topic and message if present
  if (client->will_topic != NULL) {
    packet_length += 2 + strlen(client->will_topic);
    packet_length += 2 + strlen(client->will_message);
  }
  // Username if present
  if (client->username != NULL) {
    packet_length += 2 + strlen(client->username);
  }
  // Password if present
  if (client->password != NULL) {
    packet_length += 2 + strlen(client->password);
  }
  unsigned char connect_packet_data[packet_length];
  int offset = 0;
  // Fixed header (2 bytes)
  connect_packet_data[offset++] = connect_packet.fixed_header; // Fixed header
  connect_packet_data[offset++] = packet_length - 2;           // Remaining length
  // Protocol name (6 bytes)
  connect_packet_data[offset++] = connect_packet.protocol_name.msb; // Protocol name MSB
  connect_packet_data[offset++] = connect_packet.protocol_name.lsb; // Protocol name LSB
  memcpy(&connect_packet_data[offset], connect_packet.protocol_name.data, 4);
  offset += 4;
  // Protocol version (1 byte)
  connect_packet_data[offset++] = connect_packet.protocol_version; // Protocol version
  // Connect flags (1 byte)
  connect_packet_data[offset++] = connect_packet.connect_flags; // Connect flags
  // Keep alive (2 bytes)
  connect_packet_data[offset++] = connect_packet.keep_alive >> 8; // Keep alive MSB
  connect_packet_data[offset++] = connect_packet.keep_alive & 0xFF; // Keep alive LSB
  // Connect properties (variable length)
  connect_packet_data[offset++] = 5; // properties length
  //connect_packet_data[offset++] = 0x19; // Request response information
  //connect_packet_data[offset++] = connect_packet.request_response_information;
  //connect_packet_data[offset++] = 0x17; // Request problem information
  //connect_packet_data[offset++] = connect_packet.request_problem_information;
  // Client ID (variable length)
  connect_packet_data[offset++] = connect_packet.client_id.msb;
  connect_packet_data[offset++] = connect_packet.client_id.lsb;
  memcpy(&connect_packet_data[offset], connect_packet.client_id.data, strlen(client->client_id));
  offset += strlen(client->client_id);
  // Will topic and message if present
  if (client->will_topic != NULL) {
    connect_packet_data[offset++] = connect_packet.will_topic.msb;
    connect_packet_data[offset++] = connect_packet.will_topic.lsb;
    memcpy(&connect_packet_data[offset], connect_packet.will_topic.data, strlen(client->will_topic));
    offset += strlen(client->will_topic);
    connect_packet_data[offset++] = connect_packet.will_message.msb;
    connect_packet_data[offset++] = connect_packet.will_message.lsb;
    memcpy(&connect_packet_data[offset], connect_packet.will_message.data, strlen(client->will_message));
    offset += strlen(client->will_message);
  }
  // Username if present
  if (client->username != NULL) {
    connect_packet_data[offset++] = connect_packet.username.msb;
    connect_packet_data[offset++] = connect_packet.username.lsb;
    memcpy(&connect_packet_data[offset], connect_packet.username.data, strlen(client->username));
    offset += strlen(client->username);
  }
  // Password if present
  if (client->password != NULL) {
    connect_packet_data[offset++] = connect_packet.password.msb;
    connect_packet_data[offset++] = connect_packet.password.lsb;
    memcpy(&connect_packet_data[offset], connect_packet.password.data, strlen(client->password));
    offset += strlen(client->password);
  }
  mqtt_print_packet(connect_packet_data, packet_length);
  write(client->socket, connect_packet_data, packet_length); 
  // Receive the CONNACK packet all the CONNACK packet
  printf("Receiving the CONNACK packet\n");
  unsigned char connack_packet[4];
  read(client->socket, connack_packet, 4);
  unsigned short connack_packet_length = connack_packet[1];
  mqtt_print_packet(connack_packet, 4);
  unsigned char buffer[connack_packet_length];
  read(client->socket, buffer, connack_packet_length);
  mqtt_print_packet(buffer, connack_packet_length);
  return connack_packet[3];
}

mqtt_reason_code_t mqtt_client_disconnect(mqtt_client_t *client) {
  if (client == NULL)
    return MQTT_ERROR;
  if (client->socket == 0)
    return MQTT_ERROR;
  // Send the DISCONNECT packet to the broker
  unsigned char disconnect_packet[2] = {0xE0, 0x00};
  write(client->socket, disconnect_packet, 2);
  close(client->socket);
  return MQTT_SUCCESS;
}

mqtt_reason_code_t mqtt_client_subscribe(mqtt_client_t *client, char *topic) {
  if (client == NULL)
    return MQTT_ERROR;
  if (client->socket == 0)
    return MQTT_ERROR;
  if (topic == NULL)
    return MQTT_ERROR;
  // Prepare the SUBSCRIBE packet
  // SUBSCRIBE packet is a variable header and a payload
  // Variable header is the Packet Identifier
  // Payload is the Topic Filter and QoS
  // Packet Identifier is a 16-bit integer
  unsigned char packet_identifier_msb = 0x00;
  unsigned char packet_identifier_lsb = 0x01;
  mqtt_string_t topic_filter = char_to_mqtt_string(topic);
  unsigned char qos = client->qos;
  unsigned char subscribe_packet[5 + strlen(topic)];
  subscribe_packet[0] = 0x82;
  subscribe_packet[1] = 5 + strlen(topic);
  subscribe_packet[2] = packet_identifier_msb;
  subscribe_packet[3] = packet_identifier_lsb;
  subscribe_packet[4] = topic_filter.msb;
  subscribe_packet[5] = topic_filter.lsb;
  memcpy(&subscribe_packet[6], topic_filter.data, strlen(topic));
  subscribe_packet[6 + strlen(topic)] = qos;
  write(client->socket, subscribe_packet, 7 + strlen(topic));
  // Receive the SUBACK packet
  // and return the Reason Code from the SUBACK packet
  unsigned char suback_packet[5];
  read(client->socket, suback_packet, 5);
  return suback_packet[4];
}

mqtt_reason_code_t mqtt_client_loop(mqtt_client_t *client) {
  if (client == NULL)
    return MQTT_ERROR;
  if (client->socket == 0)
    return MQTT_ERROR;
  // Loop to handle incoming messages
  while (1) {
    unsigned char fixed_header;
    read(client->socket, &fixed_header, 1);
    unsigned char remaining_length;
    read(client->socket, &remaining_length, 1);
    unsigned char packet[remaining_length];
    read(client->socket, packet, remaining_length);
    mqtt_print_packet(packet, remaining_length);
  }
}

mqtt_string_t char_to_mqtt_string(char *data) {
  mqtt_string_t mqtt_string;
  int len = strlen(data);
  mqtt_string.msb = len >> 8;
  mqtt_string.lsb = len & 0xFF;
  mqtt_string.data = data;
  return mqtt_string;
}

mqtt_connect_packet_t mqtt_create_connect_packet(mqtt_client_t *client) {
  mqtt_connect_packet_t connect_packet;
  connect_packet.fixed_header = 0x10;
  connect_packet.protocol_name = char_to_mqtt_string("MQTT");
  connect_packet.protocol_version = 5;
  connect_packet.connect_flags = 0;
  if (client->clean_session)
    connect_packet.connect_flags |= 0x02;
  if (client->will_topic != NULL) {
    connect_packet.connect_flags |= 0x04;
    if (client->will_retain)
      connect_packet.connect_flags |= 0x20;
    connect_packet.connect_flags |= client->will_qos << 3;
    connect_packet.will_topic = char_to_mqtt_string(client->will_topic);
    connect_packet.will_message = char_to_mqtt_string(client->will_message);
  }
  if (client->username != NULL) {
    connect_packet.connect_flags |= 0x80;
    connect_packet.username = char_to_mqtt_string(client->username);
  }
  if (client->password != NULL) {
    connect_packet.connect_flags |= 0x40;
    connect_packet.password = char_to_mqtt_string(client->password);
  }

  connect_packet.keep_alive = client->keep_alive;
  connect_packet.client_id = char_to_mqtt_string(client->client_id);
  // connect properties
  connect_packet.session_expiry_interval = 0;
  connect_packet.receive_maximum = 0;
  connect_packet.maximum_packet_size = 0;
  connect_packet.topic_alias_maximum = 0;
  connect_packet.request_response_information = 1;
  connect_packet.request_problem_information = 1;
  connect_packet.user_properties = 0;
  connect_packet.authentication_method = 0;
  connect_packet.authentication_data = 0;
  return connect_packet;
}

char *mqtt_reason_code_to_string(mqtt_reason_code_t reason_code,
                                 mqtt_packet_type_t packet_type) {
  switch (reason_code) {
  case MQTT_ERROR:
    return "Error";
  case 0:
    switch (packet_type) {
    case PACKET_TYPE_DISCONNECT:
      return "Normal disconnection";
    case PACKET_TYPE_SUBACK:
      return "Granted QoS 0";
    default:
      return "Success";
    }
  case MQTT_GRANTED_QOS_1:
    return "Granted QoS 1";
  case MQTT_GRANTED_QOS_2:
    return "Granted QoS 2";
  case MQTT_DISCONNECT_WITH_WILL_MESSAGE:
    return "Disconnect with will message";
  case MQTT_NO_MATCHING_SUBSCRIBERS:
    return "No matching subscribers";
  case MQTT_NO_SUBSCRIPTION_EXISTED:
    return "No subscription existed";
  case MQTT_CONTINUE_AUTHENTICATION:
    return "Continue authentication";
  case MQTT_RE_AUTHENTICATE:
    return "Re-authenticate";
  case MQTT_UNSPECIFIED_ERROR:
    return "Unspecified error";
  case MQTT_MALFORMED_PACKET:
    return "Malformed packet";
  case MQTT_PROTOCOL_ERROR:
    return "Protocol error";
  case MQTT_IMPLEMENTATION_SPECIFIC_ERROR:
    return "Implementation specific error";
  case MQTT_UNSUPPORTED_PROTOCOL_VERSION:
    return "Unsupported protocol version";
  case MQTT_CLIENT_IDENTIFIER_NOT_VALID:
    return "Client identifier not valid";
  case MQTT_BAD_USER_NAME_OR_PASSWORD:
    return "Bad user name or password";
  case MQTT_NOT_AUTHORIZED:
    return "Not authorized";
  case MQTT_SERVER_UNAVAILABLE:
    return "Server unavailable";
  case MQTT_SERVER_BUSY:
    return "Server busy";
  case MQTT_BANNED:
    return "Banned";
  case MQTT_SERVER_SHUTTING_DOWN:
    return "Server shutting down";
  case MQTT_BAD_AUTHENTICATION_METHOD:
    return "Bad authentication method";
  case MQTT_KEEP_ALIVE_TIMEOUT:
    return "Keep alive timeout";
  case MQTT_SESSION_TAKEN_OVER:
    return "Session taken over";
  case MQTT_TOPIC_FILTER_INVALID:
    return "Topic filter invalid";
  case MQTT_TOPIC_NAME_INVALID:
    return "Topic name invalid";
  default:
    return "Unknown reason code";
  }
}
