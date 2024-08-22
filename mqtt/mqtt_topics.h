#ifndef TINYSERVER_MQTT_TOPICS_H
#define TINYSERVER_MQTT_TOPICS_H

#include <internal/ts_mutex.h>
#include <internal/ts_error.h>

#define TP_LEVEL_SEPARATOR       '/'
#define TP_MULTI_LEVEL_WILDCARD  '#'
#define TP_SINGLE_LEVEL_WILDCARD '+'
#define TP_DOLLAR                '$'

typedef struct tm_topics_s tm_topics_t;
typedef struct tm_topic_node_s tm_topic_node_t;
typedef struct tm_subscribers_s tm_subscribers_t;

struct tm_subscribers_s {
    void* subscriber;
    char  qos;
    
    tm_subscribers_t* prev;
    tm_subscribers_t* next;
};

struct tm_topic_node_s {
    char* name;
    tm_subscribers_t* subscribers;
    
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


tm_topics_t* topics__create();
int topics__destroy(tm_topics_t* t);

int tm_topics__subscribe(tm_topics_t* t, const char* topic, char qos, void* subscriber);
int tm_topics__unsubscribe(tm_topics_t* t, const char* topic, void* subscriber);
int tm_topics__subscribers(tm_topics_t* t, const char* topic, char qos, tm_subscribers_t** subscribers);

int tm_topics__valid_topic_filter(const char* topic, ts_error_t* err);
int tm_topics__valid_topic_name(const char* topic, ts_error_t* err);

//TODO: Retain messages

#endif //TINYSERVER_MQTT_TOPICS_H
