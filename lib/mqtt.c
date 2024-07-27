#include "mqtt.h"
#include "connack.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PORT_STR_LEN 5

typedef struct t {
  char *topic;
  int qos;
  int retain;
  int suback_received;
  int packet_id;
  struct t *next;
} topic_list_t;

typedef struct {
  int socket;
  char *host;
  int port;
  char *client_id;
  char *username;
  char *password;
  // subscribed topics
  topic_list_t *topics;
  // subscribe handler
  mqtt_subscribe_handler_t subscribe_handler;
  pthread_t thread;
  int volatile running;
  // MQTT client configuration
  unsigned char qos;
  unsigned char retain;
  unsigned char clean_session;
  unsigned short keep_alive;
  // will
  char *will_topic;
  char *will_message;
  unsigned char will_qos;
  unsigned char will_retain;
  // packet
  unsigned short last_packet_id;
} mqtt_client_t;

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
 * The MQTT client main loop.
 *
 * @param args The arguments
 * @return NULL
 */
void *mqtt_client_main_loop(void *args);

/**
 * Handle the incoming PUBLISH packet.
 *
 * @param client The MQTT client
 * @param packet The MQTT packet
 */
void handle_incoming_publish(mqtt_client_t *client, unsigned char *packet);

/**
 * Handle the incoming SUBACK packet.
 *
 * @param client The MQTT client
 * @param packet The MQTT packet
 */
void handle_incoming_suback(mqtt_client_t *client, unsigned char *packet);

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
 * Read the MQTT packet.
 * @note The packet must be freed after use.
 * @param client The MQTT client
 * @param packet The packet
 * @return The packet length
 */
ssize_t mqtt_read_packet(mqtt_client_t *client, unsigned char **out_packet);

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

void *mqtt_client_create(char *host, int port, char *client_id, char *username,
                         char *password, unsigned char qos,
                         unsigned char retain, unsigned char clean_session,
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
  client->last_packet_id = 1;
  client->topics = NULL;
  client->subscribe_handler = NULL;
  client->topics = NULL;
  client->running = 0;
  return client;
}

void mqtt_client_destroy(void *client) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  if (c->host != NULL)
    free((char *)c->host);
  if (c->client_id != NULL)
    free((char *)c->client_id);
  if (c->username != NULL)
    free((char *)c->username);
  if (c->password != NULL)
    free((char *)c->password);
  if (c->will_topic != NULL)
    free((char *)c->will_topic);
  if (c->will_message != NULL)
    free((char *)c->will_message);
  if (c->topics != NULL) {
    topic_list_t *t = c->topics;
    while (t != NULL) {
      topic_list_t *next = t->next;
      free((char *)t->topic);
      free(t);
      t = next;
    }
  }
  free(client);
  client = NULL;
  return;
}

connack_reason_code_t mqtt_client_connect(void *client, int send_packet_only) {
  if (client == NULL)
    return CONNACK_UNSPECIFIED_ERROR;
  mqtt_client_t *c = (mqtt_client_t *)client;
  // connection guard
  if (c->host == NULL)
    return CONNACK_UNSPECIFIED_ERROR;
  if (c->port == 0)
    return CONNACK_UNSPECIFIED_ERROR;
  if (c->client_id == NULL)
    return CONNACK_UNSPECIFIED_ERROR;

  if (send_packet_only == 0) {
    // Establish the connection
    if (establish_connection(c) != 0) {
      return CONNACK_UNSPECIFIED_ERROR;
    }
  }
  // Create the CONNECT packet
  uint8_t packet[1024];
  int packet_length = create_mqtt_connect_packet(c, packet);
  // Send the CONNECT packet
  dprintf(2, "CONNECT packet:\n");
  mqtt_print_packet(packet, packet_length);
  write(c->socket, packet, packet_length);
  // Read the CONNACK packet
  dprintf(2, "CONNACK packet:\n");
  mqtt_fixed_header_t header = mqtt_read_fixed_header(c);
  mqtt_print_packet((unsigned char *)&header, sizeof(header));
  // Check the CONNACK variable header
  if (header.packet_type != (PACKET_TYPE_CONNACK >> 4)) {
    dprintf(2, "Not a CONNACK packet, packet_type:%d\n",
            header.packet_type << 4);
    ;
    return CONNACK_UNSPECIFIED_ERROR;
  }
  unsigned char variable_header[header.remaining_length];
  read(c->socket, variable_header, header.remaining_length);
  mqtt_print_packet(variable_header, header.remaining_length);
  return variable_header[1];
}

void mqtt_client_disconnect(void *client, int send_will_message) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  // Create the DISCONNECT packet
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_DISCONNECT >> 4;
  header.flags = 0x00;
  header.remaining_length = 2;
  // DISCONNECT variable header
  unsigned char variable_header[10];
  int var_header_length = 0;
  // Reason code, if send_will_message is 1 then the reason code is 0x04
  variable_header[var_header_length++] = send_will_message == 1 ? 0x04 : 0x00;
  variable_header[var_header_length++] = 0x00; // proerty length
  // Build the packet
  uint8_t packet[1024];
  memset(packet, 0, sizeof(packet));
  int packet_length = 0;
  create_mqtt_fixed_header(header, header.remaining_length, packet,
                           &packet_length);
  memcpy(packet + packet_length, variable_header, var_header_length);
  dprintf(2, "DISCONNECT packet:\n");
  mqtt_print_packet(packet, packet_length + var_header_length);
  write(c->socket, packet, packet_length + var_header_length);
  close(c->socket);
}

void mqtt_client_subscribe(void *client, char *topic) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  // Create the SUBSCRIBE packet
  mqtt_fixed_header_t header;
  header.packet_type = PACKET_TYPE_SUBSCRIBE >> 4;
  header.flags = 0x02; // they are reserved and the must be set 0010
  header.remaining_length = 0;
  // create the SUBSCRIBE variable header with the minimum length
  uint8_t variable_header[10];
  int var_header_length = 0;
  // Packet id
  uint16_t packet_id = c->last_packet_id++;
  variable_header[var_header_length++] = packet_id >> 8;
  variable_header[var_header_length++] = packet_id & 0xFF;
  // proerty length
  variable_header[var_header_length++] = 0x00;
  // Payload
  uint8_t payload[1024];
  int payload_length = 0;
  payload_length += write_string(payload + payload_length, topic);
  payload[payload_length++] = 0x00; // QoS
  // Build the packet
  // Calculate the remaining length
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
  write(c->socket, packet, packet_length + var_header_length + payload_length);
  // Add the topic to the HEAD of subscribed topics list
  topic_list_t *t = calloc(1, sizeof(topic_list_t));
  if (t == NULL)
    return;
  t->topic = strdup(topic);
  t->qos = 0;
  t->retain = 0;
  t->suback_received = 0;
  t->packet_id = packet_id;
  t->next = c->topics;
  c->topics = t;
}

void mqtt_client_publish(void *client, char *topic, char *message,
                         unsigned char qos) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
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
  // proerty length
  variable_header[var_header_length++] = 0x00;
  // Payload
  uint8_t payload[1024];
  memset(payload, 0, sizeof(payload));
  int payload_length = strlen(message);
  // write the message, we don't need to write the length
  memcpy(payload, message, strlen(message));
  // Build the packet
  header.remaining_length = var_header_length + payload_length;
  uint8_t packet[1024];
  int packet_length = 0;
  create_mqtt_fixed_header(header, header.remaining_length, packet,
                           &packet_length);
  memcpy(packet + packet_length, variable_header, var_header_length);
  memcpy(packet + packet_length + var_header_length, payload, payload_length);
  dprintf(2, "Sent PUBLISH packet:\n");
  mqtt_print_packet(packet, packet_length + var_header_length + payload_length);
  // Send the PUBLISH packet
  write(c->socket, packet, packet_length + var_header_length + payload_length);
  if (qos == 0) {
    return;
  }
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
  variable_header[var_header_length++] = 0x05; // Protocol version

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
  // Keep alive
  variable_header[var_header_length++] = client->keep_alive >> 8;
  variable_header[var_header_length++] = client->keep_alive & 0xFF;
  // proerty length
  variable_header[var_header_length++] = 0x00;
  // Payload
  payload_length += write_string(payload + payload_length, client->client_id);
  if (client->will_topic != NULL && client->will_message != NULL) {
    // will properties
    payload[payload_length++] = 0x00;
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

void mqtt_client_set_subscribe_handler(void *client,
                                       mqtt_subscribe_handler_t handler) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  c->subscribe_handler = handler;
}

void mqtt_client_loop(void *client) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  // Check if the client is already running
  if (c->running == 1) {
    return;
  }
  c->running = 1;
  // Create a thread to listen for incoming messages
  int s = pthread_create(&c->thread, NULL, mqtt_client_main_loop, client);
  if (s != 0) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }
}

void mqtt_client_stop(void *client) {
  if (client == NULL)
    return;
  mqtt_client_t *c = (mqtt_client_t *)client;
  // Stop the thread
  c->running = 0;
  // Wait for the thread to finish
  pthread_join(c->thread, NULL);
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

void *mqtt_client_main_loop(void *args) {
  mqtt_client_t *client = (mqtt_client_t *)args;
  // Perform non blocking I/O with the poll(2) system call
  struct pollfd fds[1];
  fds[0].fd = client->socket;
  fds[0].events = POLLIN;
  fds[0].revents = 0;
  while (client->running) {
    // Polling the socket with a timeout of 1 second
    // to check if there is data to read
    int ret = poll(fds, 1, 1000);
    if (ret == -1) {
      perror("poll");
      break;
    }
    if (ret == 0) {
      // Timeout
      sched_yield();
      continue;
    }
    // if the socket is not ready to read, continue
    if (!(fds[0].revents & POLLIN)) {
      sched_yield();
      continue;
    }
    // Read the incoming packet
    unsigned char *packet = NULL;
    ssize_t n = mqtt_read_packet(client, &packet);
    if (n == 0 || packet == NULL) {
      continue;
    }
    // Handle the packet type
    uint8_t packet_type = packet[0];
    switch (packet_type) {
    case PACKET_TYPE_PUBLISH:
      dprintf(2, "Received PUBLISH packet\n");
      mqtt_print_packet(packet, n);
      handle_incoming_publish(client, packet);
      break;
    case PACKET_TYPE_SUBACK:
      dprintf(2, "Received SUBACK packet\n");
      mqtt_print_packet(packet, n);
      handle_incoming_suback(client, packet);
      break;
    default:
      dprintf(2, "Unknown packet type: %d\n", packet_type);
      break;
    }
    free(packet);
    packet = NULL;
    sched_yield();
  }
  dprintf(2, "Main loop finished\n");
  pthread_exit(NULL);
}

void handle_incoming_publish(mqtt_client_t *client, unsigned char *packet) {
  // Parse the incoming PUBLISH packet
  mqtt_fixed_header_t header;
  header.flags = packet[0] & 0x0F;
  header.remaining_length = packet[1];
  int qos = (header.flags >> 1) & 0x03;
  int offset = 2;
  // Variable header
  // proerty length
  uint16_t property_length = packet[offset];
  offset += 1 + property_length;

  mqtt_string_t topic;
  topic.length = (packet[2] << 8) | (packet[3] & 0xFF);
  topic.data = calloc(1, topic.length + 1);
  if (topic.data == NULL) {
    return;
  }
  offset += 2;

  memcpy(topic.data, packet + offset, topic.length + 1);
  topic.data[topic.length] = '\0';
  offset += topic.length;
  if (qos > 0) {
    // Packet id
    // uint16_t packet_id = (packet[offset] << 8) | (packet[offset + 1] & 0xFF);
    offset += 2;
    // proerty length
    // uint16_t property_length = (packet[offset] << 8) | (packet[offset + 1] &
    // 0xFF);
    offset += 2;
  }

  // Payload, the message, is the remaining data, the length is the remaining
  // length minus the topic length The message must be freed by the handler
  mqtt_string_t message;
  message.length = header.remaining_length - topic.length;
  message.data = calloc(1, message.length + 1);
  memcpy(message.data, packet + offset, message.length - 2);
  message.data[message.length] = '\0';
  // Print only the message as bytes using the packet and the offset
  // Call the subscribe handler
  // The message must be freed by the handler
  mqtt_message_t mqtt_message;
  mqtt_message.topic = topic.data;
  mqtt_message.message = message.data;
  if (client->subscribe_handler != NULL) {
    client->subscribe_handler(&mqtt_message);
  }
}

void handle_incoming_suback(mqtt_client_t *client, unsigned char *packet) {
  // Parse the incoming SUBACK packet
  mqtt_fixed_header_t header;
  header.packet_type = packet[0] >> 4;
  header.flags = packet[0] & 0x0F;
  header.remaining_length = packet[1];
  // Payload
  int index = 2;
  // Packet id
  uint16_t packet_id = (packet[index] << 8) | (packet[index + 1] & 0xFF);
  index += 2;
  // Propery length
  int property_length = packet[index++];
  index += property_length;
  // Add the fixed header len to the remaining length
  header.remaining_length += 2;
  while (index < header.remaining_length) {
    // Read the QoS level
    int qos = packet[index++];
    // Update the last topic without a suback
    topic_list_t *t = client->topics;
    while (t != NULL) {
      if (t->packet_id == packet_id && (t->suback_received == 0)) {
        t->suback_received = 1;
        t->qos = qos;
        dprintf(2, "Subscribed to topic: %s, QoS: %d\n", t->topic, t->qos);
        break;
      }
      t = t->next;
    }
  }
}

ssize_t mqtt_read_packet(mqtt_client_t *client, unsigned char **out_packet) {
  unsigned char buf[1024];
  memset(buf, 0, sizeof(buf));
  // Always read the fixed header
  ssize_t n = read(client->socket, buf, 2);
  if (n < 0) {
    perror("read");
    exit(EXIT_FAILURE);
  }
  if (n == 0) {
    return 0;
  }
  ssize_t remaining_length = buf[1];
  // check if i already have the remaining length
  if (n < 2 + remaining_length) {
    // read the remaining length
    while (n < 2 + remaining_length) {
      ssize_t m = read(client->socket, buf + n, remaining_length);
      if (m < 0) {
        perror("read");
        exit(EXIT_FAILURE);
      }
      n += m;
    }
  }
  // Put the packet in the out_packet variable
  // The packet must be freed by the caller
  *out_packet = calloc(1, n + 1);
  memcpy(*out_packet, buf, n);
  // Add the \0 character to the end of the packet
  (*out_packet)[n] = '\0';
  return n;
}

void mqtt_message_destroy(mqtt_message_t *message) {
  if (message == NULL)
    return;
  if (message->topic != NULL)
    free(message->topic);
  if (message->message != NULL)
    free(message->message);
  message = NULL;
}
