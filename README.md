# MQTT Client

This is a simple (and shitty) MQTT C client library used for emulating a MQTT network traffic.

## Why?

I needed a simple MQTT client in order to create a network traffic for one of my exams. I needed a DDoS and DoS attack simulation, so I created this simple client to help me with that.
Maybe I will improve this shit in the future.

## How to use

1. Clone the repository
2. Run `make` to compile the client, you can modify the client code to suit your testing needs.
3. Run the client with `./mqtt-client <number of clients>` to start the clients

This example will start N clients that will connect to the broker and publish a message non-stop.

## Configuration

For now, the program is hardcoded in order to check if the packages are being sent correctly. You can change the broker address and port in the `client.c`. The topic and message are also hardcoded in the `client.c` file.

## MQTT Library

With this shitty implementation of MQTT protocol, you can:

- Connect to a broker (with anonymous authentication, no TLS)
- Publish messages
- Disconnect from the broker

## TODO

- Implement the QoS levels
- Implement the subscribe method
- Implement the keep alive mechanism
- Implement the last will message
- Implement the authentication
