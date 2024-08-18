#ifndef TINYSERVER_TOPICS_H
#define TINYSERVER_TOPICS_H

#include <internal/ts_mutex.h>
#include <internal/ts_error.h>

#define TP_LEVEL_SEPARATOR       '/'
#define TP_MULTI_LEVEL_WILDCARD  '#'
#define TP_SINGLE_LEVEL_WILDCARD '+'
#define TP_DOLLAR                '$'

typedef struct tm_topics_s tm_topics_t;
typedef struct tm_subnode_s tm_subnode_t;
typedef struct tm_subscribers_s tm_subscribers_t;

struct tm_subscribers_s {
    void* subscriber;
    char  qos;
    
    tm_subscribers_t* prev;
    tm_subscribers_t* next;
};

// subscription nodes
struct tm_subnode_s {
    char* name;
    tm_subscribers_t* subscribers;
    
    tm_subnode_t* children;
    
    tm_subnode_t* parent;
    tm_subnode_t* prev;
    tm_subnode_t* next;
};

struct tm_topics_s {
    ts_mutex_t   sub_mu;
    tm_subnode_t sub_root;
    
    ts_error_t err;
};


tm_topics_t* topics__create();
int topics__destroy(tm_topics_t* t);

int tm_topics__subscribe(tm_topics_t* t, const char* topic, char qos, void* subscriber);
int tm_topics__unsubscribe(tm_topics_t* t, const char* topic, void* subscriber);
int tm_topics__subscribers(tm_topics_t* t, const char* topic, char qos, tm_subscribers_t** subscribers);

//TODO: Retain messages

#endif //TINYSERVER_TOPICS_H
