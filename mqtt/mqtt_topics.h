#ifndef TINYSERVER_MQTT_TOPICS_H
#define TINYSERVER_MQTT_TOPICS_H

#include <internal/ts_mutex.h>
#include <internal/ts_error.h>
#include <internal/ts_array.h>
#include <internal/ts_int_array.h>
#include <internal/uthash.h>

#include "mqtt_message.h"

#define TP_LEVEL_SEPARATOR       '/'
#define TP_MULTI_LEVEL_WILDCARD  '#'
#define TP_SINGLE_LEVEL_WILDCARD '+'
#define TP_DOLLAR                '$'

typedef struct tm_topics_s tm_topics_t;
typedef struct tm_topic_node_s tm_topic_node_t;
typedef struct tm_subscribers_s tm_subscribers_t;
typedef struct tm_matched_subscriber_s tm_matched_subscriber_t;

struct tm_matched_subscriber_s {
    void* subscriber;
    ts_int_arr_t* qoss;
    
    UT_hash_handle hh; // make this struct hashable
};

// 'subscribers', 's' is meant here.
void tm_matched_subscribers__destroy(tm_matched_subscriber_t* subscribers);
int tm_matched_subscribers__count(tm_matched_subscriber_t* subscribers);

struct tm_subscribers_s {
    void* subscriber;
    char  qos;
    
    tm_subscribers_t* prev;
    tm_subscribers_t* next;
};

struct tm_topic_node_s {
    char* name;

    tm_subscribers_t* subscribers;

    tm_mqtt_msg_t* retained_msg;
    
    tm_topic_node_t* children;
    
    tm_topic_node_t* parent;
    tm_topic_node_t* prev;
    tm_topic_node_t* next;
};

struct tm_topics_s {
    ts_mutex_t   mu;
    tm_topic_node_t root;
    
    ts_error_t err;
};


tm_topics_t* tm_topics__create();
int tm_topics__destroy(tm_topics_t* t);

int tm_topics__subscribe(tm_topics_t* t, const char* topic, char qos, void* subscriber);
int tm_topics__unsubscribe(tm_topics_t* t, const char* topic, void* subscriber);
int tm_topics__subscribers(tm_topics_t* t, const char* topic, char qos, tm_matched_subscriber_t** subscribers);
int tm_topics__subscribers_free(tm_subscribers_t* subscribers);

int tm_topics__retain_msg(tm_topics_t* t, tm_mqtt_msg_t* msg, tm_mqtt_msg_t** removed_retained_msg);
int tm_topics__get_retained_msgs(tm_topics_t* t, const char* topic, ts_ptr_arr_t* retained_msgs);

int tm_topics__valid_topic_filter(const char* topic, int topic_len, ts_error_t* err);
int tm_topics__valid_topic_name(const char* topic, int topic_len, ts_error_t* err);

#endif //TINYSERVER_MQTT_TOPICS_H
