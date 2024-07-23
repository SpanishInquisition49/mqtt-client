#include "mqtt.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

mqtt_message_t *mqtt_create(unsigned char type, unsigned char flags,
                            unsigned short lenght, unsigned char *data) {
  mqtt_message_t *message = calloc(1, sizeof(mqtt_message_t));
  if (message == NULL)
    return NULL;

  message->type = type;
  message->flags = flags;
  message->lenght = lenght;
  message->data = data;
  return message;
}

void mqtt_destroy(mqtt_message_t *message) {
  if (message == NULL)
    return;

  if (message->data != NULL)
    free(message->data);
  free(message);
  message = NULL;
}

mqtt_client_t *mqtt_client_create(char *host, int port, char *client_id,
                                  char *username, char *password,
                                  unsigned char qos, unsigned char retain,
                                  unsigned char clean_session,
                                  unsigned short keep_alive) {
  mqtt_client_t *client = calloc(1, sizeof(mqtt_client_t));
  if (client == NULL)
    return NULL;

  client->host = host;
  client->port = port;
  client->client_id = client_id;
  client->username = username;
  client->password = password;
  client->topics = NULL;
  client->qos = qos;
  client->retain = retain;
  client->clean_session = clean_session;
  client->keep_alive = keep_alive;
  return client;
}

void mqtt_client_destroy(mqtt_client_t *client) {
  free(client->host);
  free(client->client_id);
  free(client->username);
  free(client->password);
  for (int i = 0; i < client->subscribed_topics; i++)
    free(client->topics[i]);
  free(client->topics);
  free(client);
  client = NULL;
  return;
}

mqtt_error_t mqtt_client_connect(mqtt_client_t *client) {
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    perror("socket");
    return SOCKET_ERROR;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(client->port);
  server_addr.sin_addr.s_addr = inet_addr(client->host);

  if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("connect");
    return CONNECT_ERROR;
  }
  client->socket = socket_fd;
  return OK;
}

mqtt_error_t mqtt_client_disconnect(mqtt_client_t *client) {
  // Send DISCONNECT message to the broker
  unsigned char data[] = {MQTT_DISCONNECT, 0x00};
  write(client->socket, data, sizeof(data));
  // close the socket
  close(client->socket);
  return OK;
}

mqtt_error_t mqtt_client_subscribe(mqtt_client_t *client, char *topic) {
  // check if the topic is already subscribed
  if (mqtt_client_is_subscribed(client, topic))
    return TOPIC_ALREADY_SUBSCRIBED;
  // prepare the SUB message
  unsigned char data[2 + strlen(topic) + 1];
  data[0] = MQTT_SUBSCRIBE | (client->qos << 1);
  data[1] = strlen(topic);
  strcpy((char *)&data[2], topic);
  write(client->socket, data, sizeof(data));
  // wait for the SUBACK message
  unsigned char buffer[5];
  read(client->socket, buffer, sizeof(buffer));
  if (buffer[0] != (MQTT_SUBACK | (client->qos << 1)))
    return SUBACK_NOT_RECEIVED;
  ;
  client->subscribed_topics++;
  client->topics =
      realloc(client->topics, client->subscribed_topics * sizeof(char *));
  client->topics[client->subscribed_topics - 1] = topic;
  return OK;
}

mqtt_error_t mqtt_client_publish(mqtt_client_t *client, char *topic,
                                 char *payload) {
  // prepare the PUBLISH message
  // fixed header
  // 1 byte for the message type and flags
  // 1 byte for the remaining lenght
  // variable header
  // 2 bytes for the topic lenght
  // N bytes for the topic
  // 2 bytes for the message id
  // payload
  // N bytes for the payload
  unsigned short topic_length = strlen(topic);
  unsigned short payload_length = strlen(payload);
  unsigned short message_length = 2 + topic_length + 2 + payload_length;
  unsigned char data[1 + 1 + 2 + topic_length + 2 + payload_length];
  data[0] = MQTT_PUBLISH | (client->qos << 1);
  data[1] = message_length;
  data[2] = topic_length >> 8;
  data[3] = topic_length & 0xFF;
  strcpy((char *)&data[4], topic);
  data[4 + topic_length] = 0x00;
  data[5 + topic_length] = 0x01;
  strcpy((char *)&data[6 + topic_length], payload);
  write(client->socket, data, sizeof(data));
  // if QoS is 0, we don't need to wait for the PUBACK message
  if (client->qos == MQTT_QOS_0)
    return OK;
  // if QoS is 1, we need to wait for the PUBACK message
  if (client->qos == MQTT_QOS_1) {
    unsigned char buffer[4];
    read(client->socket, buffer, sizeof(buffer));
    if (buffer[0] != (MQTT_PUBACK | (client->qos << 1)))
      return PUBACK_NOT_RECEIVED;
  }
  // if QoS is 2, we need to wait for the PUBREC message and send the PUBREL
  // message
  if (client->qos == MQTT_QOS_2) {
    unsigned char buffer[4];
    read(client->socket, buffer, sizeof(buffer));
    if (buffer[0] != (MQTT_PUBREC | (client->qos << 1)))
      return PUBREC_NOT_RECEIVED;
    unsigned char data[4] = {MQTT_PUBREL | (client->qos << 1), 0x02, buffer[2],
                             buffer[3]};
    write(client->socket, data, sizeof(data));
    read(client->socket, buffer, sizeof(buffer));
    if (buffer[0] != (MQTT_PUBCOMP | (client->qos << 1)))
      return PUBCOMP_NOT_RECEIVED;
  }
  return OK;
}

int mqtt_client_is_subscribed(mqtt_client_t *client, char *topic) {
  for (int i = 0; i < client->subscribed_topics; i++)
    if (strcmp(client->topics[i], topic) == 0)
      return 1;
  return 0;
}
