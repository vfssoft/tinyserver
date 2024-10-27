
#ifndef TINYSERVER_TEST_MQTT_MSGS_H
#define TINYSERVER_TEST_MQTT_MSGS_H

typedef struct msg_s msg_t;
typedef struct msgs_s msgs_t;

struct msg_s {
    char* topic;
    int payload_len;
    char* payload;
    int qos;
    int retained;
    int dup;
};

msg_t* msg__create(const char* topic, const char* payload, int payload_len, int qos, int retained, int dup);
void msg__destroy(msg_t* m);
msg_t* msg__clone(msg_t* m);

struct msgs_s {
    msg_t** buf;
    int count;
    int cap;
};

msgs_t* msgs__create(int cap);
void msgs__destroy(msgs_t* msgs);
msgs_t* msgs__clone(msgs_t* msgs);
void msgs__add(msgs_t* msgs, msg_t* m);
void msgs__add2(msgs_t* msgs, const char* topic, const char* payload, int payload_len, int qos, int retained, int dup);
int msgs__count(msgs_t* msgs);
msg_t* msgs__at(msgs_t* msgs, int idx);


#endif //TINYSERVER_TEST_MQTT_MSGS_H
