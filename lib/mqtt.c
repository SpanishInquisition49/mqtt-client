#include "mqtt.h"
#include "connack.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PORT_STR_LEN 5

/**
 * The MQTT fixed header
 *
 */
typedef struct {
  uint8_t packet_type : 4;
  uint8_t flags : 4;
  uint8_t remaining_length;
} mqtt_fixed_header_t;

typedef struct {
  uint16_t length;
  char *data;
} mqtt_string_t;

/**
 * The MQTT connect variable header
 */
typedef struct {
  uint8_t protocol_name_length; // 2 bytes
  char protocol_name[4];        // 4 bytes
  uint8_t protocol_version;     // 1 byte
  uint8_t connect_flags; // 1 byte (username, password, will retain, will qos,
                         // will, clean session)
  uint16_t keep_alive;   // 2 bytes
  uint8_t properties_length;
} mqtt_connect_variable_header_t;

/**
 * Encode the remaining length.
 *
 * @param buf The buffer
 * @param length The length
 * @return The number of bytes used to encode the length
 */
int encode_remaining_length(uint8_t *buf, uint32_t length);

/**
 * Decode the remaining length.
 *
 * @param buf The buffer
 * @param length The length
 * @return The number of bytes used to encode the length
 */
int decode_remaining_length(uint8_t *buf, uint32_t *length);

/**
 * Write a string with its length.
 *
 * @param buf The buffer
 * @param str The string
 * @return The number of bytes written
 */
int write_string(uint8_t *buf, const char *str);

/**
 * Create the MQTT coonect packet
 *
 * @param client The MQTT client
 * @param packet The packet
 * @return The length of the packet:w
 */
int create_mqtt_connect_packet(mqtt_client_t *client, uint8_t *packet);

/**
 * Establish the connection.
 *
 * @param client The MQTT client
 * @return 0 if successful, -1 otherwise
 */
int establish_connection(mqtt_client_t *client);

/**
 * Read the MQTT fixed header.
 *
 * @param client The MQTT client
 * @return The fixed header
 */
mqtt_fixed_header_t mqtt_read_fixed_header(mqtt_client_t *client) {
  unsigned char buf[2];
  read(client->socket, buf, 2);
  mqtt_fixed_header_t header;
  header.packet_type = buf[0] >> 4;
  header.flags = buf[0] & 0x0F;
  header.remaining_length = buf[1];
  return header;
}

/**
 * Create the MQTT fixed header.
 *
 * @param packet_type The packet type
 * @param flags The flags
 * @param remaining_length The remaining length
 * @return The fixed header
 */
void create_mqtt_fixed_header(mqtt_fixed_header_t header,
                              uint32_t remaining_length, uint8_t *fixed_header,
                              int *header_length) {
  int index = 0;
  fixed_header[index++] = (header.packet_type << 4) | (header.flags & 0x0F);

  // Encode the remaining length
  index += encode_remaining_length(&fixed_header[index], remaining_length);

  *header_length = index;
}

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

connack_reason_code_t mqtt_client_connect(mqtt_client_t *client,
                                          int send_packet_only) {
  // connection guard
  if (client->host == NULL)
    return CONNACK_UNSPECIFIED_ERROR;
  if (client->port == 0)
    return CONNACK_UNSPECIFIED_ERROR;
  if (client->client_id == NULL)
    return CONNACK_UNSPECIFIED_ERROR;

  if (send_packet_only == 0) {
    // Establish the connection
    if (establish_connection(client) != 0) {
      return CONNACK_UNSPECIFIED_ERROR;
    }
  }
  // Create the CONNECT packet
  uint8_t packet[1024];
  int packet_length = create_mqtt_connect_packet(client, packet);
  // Send the CONNECT packet
  dprintf(2, "CONNECT packet:\n");
  mqtt_print_packet(packet, packet_length);
  write(client->socket, packet, packet_length);
  // Read the CONNACK packet
  dprintf(2, "CONNACK packet:\n");
  mqtt_fixed_header_t header = mqtt_read_fixed_header(client);
  mqtt_print_packet((unsigned char *)&header, sizeof(header));
  // Check the CONNACK variable header
  if (header.packet_type != (PACKET_TYPE_CONNACK >> 4)) {
    dprintf(2, "Not a CONNACK packet, packet_type:%d\n",
            header.packet_type << 4);
    ;
    return CONNACK_UNSPECIFIED_ERROR;
  }
  unsigned char variable_header[header.remaining_length];
  read(client->socket, variable_header, header.remaining_length);
  mqtt_print_packet(variable_header, header.remaining_length);
  return variable_header[1];
}

void mqtt_client_disconnect(mqtt_client_t *client) {
  // Create the DISCONNECT packet
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_DISCONNECT >> 4;
  header.flags = 0x00;
  header.remaining_length = 1;
  // create the DISCONNECT variable header
  uint8_t variable_header[10];
  int var_header_length = 0;
  // disconnect reason code
  variable_header[var_header_length++] = 0x00;
  // Build the packet
  uint8_t packet[1024];
  int packet_length = 0;
  create_mqtt_fixed_header(header, header.remaining_length, packet,
                           &packet_length);
  memcpy(packet + packet_length, variable_header, var_header_length);
  dprintf(2, "DISCONNECT packet:\n");
  mqtt_print_packet(packet, packet_length + var_header_length);
  // Send the DISCONNECT packet
  write(client->socket, &header, sizeof(header));
  close(client->socket);
}

void mqtt_client_subscribe(mqtt_client_t *client, char *topic) {
  // Create the SUBSCRIBE packet
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_SUBSCRIBE >> 4;
  header.flags = 0x02;
  header.remaining_length = 0;
  // create the SUBSCRIBE variable header
  uint8_t variable_header[10];
  int var_header_length = 0;
  uint16_t packet_id = 1;
  variable_header[var_header_length++] = packet_id >> 8;
  variable_header[var_header_length++] = packet_id & 0xFF;
  // create the SUBSCRIBE payload
  uint8_t payload[1024];
  int payload_length = 0;
  payload_length += write_string(payload + payload_length, topic);
  payload[payload_length++] = 0x00; // QoS
  // Build the packet
  header.remaining_length = var_header_length + payload_length;
  uint8_t packet[1024];
  int packet_length = 0;
  create_mqtt_fixed_header(header, header.remaining_length, packet,
                           &packet_length);
  memcpy(packet + packet_length, variable_header, var_header_length);
  memcpy(packet + packet_length + var_header_length, payload, payload_length);
  dprintf(2, "SUBSCRIBE packet:\n");
  mqtt_print_packet(packet, packet_length + var_header_length + payload_length);
  // Send the SUBSCRIBE packet
  write(client->socket, packet,
        packet_length + var_header_length + payload_length);
  // Read the SUBACK packet
  mqtt_fixed_header_t suback_header = mqtt_read_fixed_header(client);
  unsigned char suback_variable_header[suback_header.remaining_length];
  dprintf(2, "SUBACK packet:\n");
  read(client->socket, suback_variable_header, suback_header.remaining_length);
  mqtt_print_packet((unsigned char *)&suback_header, sizeof(suback_header));
  mqtt_print_packet(suback_variable_header, suback_header.remaining_length);
}

void mqtt_client_publish(mqtt_client_t *client, char *topic, char *message,
                         unsigned char qos) {
  // Create the PUBLISH packet
  // Fixed header
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_PUBLISH >> 4;
  header.flags = 0x00;
  header.remaining_length = 0;
  // Variable header
  uint8_t variable_header[10];
  int var_header_length = 0;
  var_header_length += write_string(variable_header + var_header_length, topic);
  if (qos > 0) {
    // Packet id
    uint16_t packet_id = 1;
    variable_header[var_header_length++] = packet_id >> 8;
    variable_header[var_header_length++] = packet_id & 0xFF;
  }
  // Payload
  uint8_t payload[1024];
  int payload_length = 0;
  payload_length += write_string(payload + payload_length, message);
  // Build the packet
  header.remaining_length = var_header_length + payload_length;
  uint8_t packet[1024];
  int packet_length = 0;
  create_mqtt_fixed_header(header, header.remaining_length, packet,
                           &packet_length);
  memcpy(packet + packet_length, variable_header, var_header_length);
  memcpy(packet + packet_length + var_header_length, payload, payload_length);
  dprintf(2, "PUBLISH packet:\n");
  mqtt_print_packet(packet, packet_length + var_header_length + payload_length);
  // Send the PUBLISH packet
  write(client->socket, packet,
        packet_length + var_header_length + payload_length);
  if (qos == 0) {
    return;
  }
  // Read the PUBACK packet
  mqtt_fixed_header_t puback_header = mqtt_read_fixed_header(client);
  unsigned char puback_variable_header[puback_header.remaining_length];
  dprintf(2, "PUBACK packet:\n");
  read(client->socket, puback_variable_header, puback_header.remaining_length);
  mqtt_print_packet((unsigned char *)&puback_header, sizeof(puback_header));
  mqtt_print_packet(puback_variable_header, puback_header.remaining_length);
}

// Function to create an MQTT CONNECT packet
int create_mqtt_connect_packet(mqtt_client_t *client, uint8_t *packet) {
  uint8_t fixed_header[10]; // Buffer to hold the fixed header (maximum 10
                            // bytes should be enough)
  int header_length;

  uint8_t variable_header[10];
  int var_header_length = 0;

  uint8_t payload[1024];
  memset(payload, 0, sizeof(payload));
  int payload_length = 0;

  // Variable header
  var_header_length += write_string(variable_header + var_header_length,
                                    "MQTT");   // Protocol name
  variable_header[var_header_length++] = 0x04; // Protocol version

  // Connect flags
  uint8_t connect_flags = 0x00;
  if (client->username != NULL) {
    connect_flags |= 0x80; // Username flag
  }
  if (client->password != NULL) {
    connect_flags |= 0x40; // Password flag
  }
  if (client->will_retain) {
    connect_flags |= 0x20; // Will retain flag
  }
  connect_flags |= client->will_qos << 3; // Will QoS
  if (client->will_topic != NULL) {
    connect_flags |= 0x04; // Will flag
  }
  if (client->clean_session) {
    connect_flags |= 0x02; // Clean session flag
  }
  variable_header[var_header_length++] = connect_flags;

  variable_header[var_header_length++] = client->keep_alive >> 8;
  variable_header[var_header_length++] = client->keep_alive & 0xFF;

  // Payload
  payload_length += write_string(payload + payload_length, client->client_id);
  if (client->will_topic != NULL && client->will_message != NULL) {
    payload[payload_length++] = 0x00; // will properties length
    payload_length +=
        write_string(payload + payload_length, client->will_topic);
    payload_length +=
        write_string(payload + payload_length, client->will_message);
  }
  if (client->username != NULL) {
    payload_length += write_string(payload + payload_length, client->username);
  }
  if (client->password != NULL) {
    payload_length += write_string(payload + payload_length, client->password);
  }

  // Fixed header
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_CONNECT >> 4;
  header.flags = 0x00; // No flags for this example
  uint32_t remaining_length = var_header_length + payload_length;

  create_mqtt_fixed_header(header, remaining_length, fixed_header,
                           &header_length);

  // Assemble packet
  memcpy(packet, fixed_header, header_length);
  memcpy(packet + header_length, variable_header, var_header_length);
  memcpy(packet + header_length + var_header_length, payload, payload_length);

  return header_length + var_header_length + payload_length;
}

int encode_remaining_length(uint8_t *buf, uint32_t length) {
  int i = 0;
  do {
    uint8_t encodedByte = length % 128;
    length /= 128;
    // if there are more data to encode, set the top bit of this byte
    if (length > 0) {
      encodedByte |= 0x80;
    }
    buf[i++] = encodedByte;
  } while (length > 0);

  return i; // Return the number of bytes used to encode the length
}

int decode_remaining_length(uint8_t *buf, uint32_t *length) {
  int i = 0;
  uint32_t multiplier = 1;
  *length = 0;
  uint8_t encodedByte;

  do {
    encodedByte = buf[i++];
    *length += (encodedByte & 127) * multiplier;
    if (multiplier > 128 * 128 * 128) {
      // Invalid remaining length
      return -1;
    }
    multiplier *= 128;
  } while ((encodedByte & 128) != 0);

  return i; // Return the number of bytes used to encode the length
}

// Function to write a string with its length
int write_string(uint8_t *buf, const char *str) {
  int len = strlen(str);
  buf[0] = (uint8_t)(len >> 8);
  buf[1] = (uint8_t)(len & 0xFF);
  memcpy(buf + 2, str, len);
  return len + 2;
}

int establish_connection(mqtt_client_t *client) {
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
    return -1;
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
    return -1;
  }
  client->socket = sfd;
  return 0;
}
