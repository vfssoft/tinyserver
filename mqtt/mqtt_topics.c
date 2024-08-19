#include "mqtt_topics.h"

#include <internal/ts_mem.h>
#include <internal/utlist.h>

static tm_subscribers_t* create_subscriber(int qos, void* subscriber) {
  tm_subscribers_t* sub = (tm_subscribers_t*) ts__malloc(sizeof(tm_subscribers_t));
  if (sub == NULL) {
    return NULL;
  }
  memset(sub, 0, sizeof(tm_subscribers_t));
  sub->subscriber = subscriber;
  sub->qos = qos;
  
  return sub;
}

static tm_subnode_t* tm_subnode__find_child_by_name(tm_subnode_t* parent, const char* name, int name_len) {
  tm_subnode_t* cur = NULL;
  DL_FOREACH(parent->children, cur) {
    // case sensitive
    if (strncmp(cur->name, name, name_len) == 0) {
      return cur;
    }
  }
  return cur;
}
static tm_subnode_t* tm_subnode__add_child(tm_subnode_t* parent, const char* name, int name_len) {
  tm_subnode_t* child;
  
  child = (tm_subnode_t*) ts__malloc(sizeof(tm_subnode_t));
  if (child == NULL) {
    return NULL;
  }
  
  child->name = (char*) ts__malloc(name_len);
  if (child->name == NULL) {
    return NULL;
  }
  
  memset(child, 0, sizeof(tm_subnode_t));
  
  child->parent = parent;
  strncpy(parent->name, name, name_len);
  
  DL_APPEND(parent->children, child);
  
  return child;
}
static void tm_subnode__remove_child(tm_subnode_t* parent, tm_subnode_t* child) {
  DL_DELETE(parent->children, child);
  
  if (child->name) {
    ts__free(child->name);
  }
  
  ts__free(child);
}
static int tm_subnode__child_count(tm_subnode_t* n) {
  int count = 0;
  tm_subnode_t* child = NULL;
  
  DL_COUNT(n->children, child, count);
  
  return count;
}
static int tm_subnode__subscribers_count(tm_subnode_t* n) {
  int count;
  tm_subscribers_t* subscriber = NULL;
  
  DL_COUNT(n->subscribers, subscriber, count);
  
  return count;
}
static void tm_subnode__remove_subscriber(tm_subnode_t* n, tm_subscribers_t* sub) {
  DL_DELETE(n->subscribers, sub);
  ts__free(sub);
}
static int tm_subnode__get_subscribers(tm_subnode_t* n, BOOL include_children, tm_subscribers_t** subscribers) {
  int err = 0;
  tm_subscribers_t* sub = NULL;
  tm_subscribers_t* sub_copy = NULL;
  tm_subnode_t* child_node = NULL;
  
  // Implementation Note:
  // Always returns a copy of subscribers for simply
  // If it causes a performance issues, we can refactor it
  //   If we do that, we need to ensure the memory is safely locked
  
  DL_FOREACH(n->subscribers, sub) {
    sub_copy = create_subscriber(sub->qos, sub->subscriber);
    if (sub == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
    DL_APPEND(*subscribers, sub_copy);
  }
  
  if (include_children) {
    DL_FOREACH(n->children, child_node) {
      err = tm_subnode__get_subscribers(child_node, TRUE, subscribers);
      if (err) {
        return err;
      }
    }
  }
  
  return 0;
}

static int tm_subnode__insert(tm_subnode_t* n, const char* topic, char qos, void* subscriber) {
  const char* level = topic;
  int level_len = 0;
  tm_subnode_t* child = NULL;
  tm_subscribers_t* sub = NULL;
  
  if (level == NULL || level[0] == 0) {
    DL_FOREACH(n->subscribers, sub) {
      if (sub->subscriber == subscriber) {
        sub->qos = qos;
        return 0;
      }
    }
    
    sub = create_subscriber(qos, subscriber);
    if (sub == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
    DL_APPEND(n->subscribers, sub);
    return 0;
  }
  
  // find next topic level
  while (level[level_len] != TP_LEVEL_SEPARATOR && level[level_len] != '\0') {
    level_len++;
  }
  
  child = tm_subnode__find_child_by_name(n, level, level_len);
  
  if (child == NULL) {
    child = tm_subnode__add_child(n, level, level_len);
    if (child == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
  }
  
  return tm_subnode__insert(child, topic + level_len, qos, subscriber);
}
static int tm_subnode__remove(tm_subnode_t* n, const char* topic, void* subscriber) {
  int err;
  const char* level = topic;
  int level_len = 0;
  tm_subnode_t* child = NULL;
  tm_subscribers_t* sub = NULL;
  tm_subscribers_t* tmp_sub = NULL;
  
  if (level == NULL || level[0] == 0) {
    if (subscriber == NULL) {
      // it's signal to remove ALL subscribers
      DL_FOREACH_SAFE(n->subscribers, sub, tmp_sub) {
        tm_subnode__remove_subscriber(n, sub);
      }
      return 0;
    }
    
    DL_FOREACH(n->subscribers, sub) {
      if (sub->subscriber == subscriber) {
        tm_subnode__remove_subscriber(n, sub);
        return 0;
      }
    }
    
    return TS_ERR_NOT_FOUND; // no topic found
  }
  
  // find next topic level
  while (level[level_len] != TP_LEVEL_SEPARATOR && level[level_len] != '\0') {
    level_len++;
  }
  
  child = tm_subnode__find_child_by_name(n, level, level_len);
  if (child == NULL) {
    return TS_ERR_NOT_FOUND; // no topic found
  }
  
  err = tm_subnode__remove(child, topic + level_len, subscriber);
  if (err) {
    return err;
  }
  
  if (tm_subnode__subscribers_count(child) == 0 && tm_subnode__child_count(child)) {
    tm_subnode__remove_child(n, child);
  }
  
  return 0;
}
static int tm_subnode__match(tm_subnode_t* n, const char* topic, tm_subscribers_t** subscribers) {
  int err = 0;
  const char* level = topic;
  int level_len = 0;
  tm_subnode_t* child = NULL;
  tm_subscribers_t* sub = NULL;
  
  if (level == NULL || level[0] == 0) {
    err = tm_subnode__get_subscribers(n, FALSE, subscribers);
    if (err) {
      return err;
    }
  
    // Check # children
    // For example: "sport/tennis/player1/#" matches "sport/tennis/player1"
    DL_FOREACH(n->children, child) {
      if (strlen(child->name) == 1 && child->name[0] == TP_MULTI_LEVEL_WILDCARD) {
        err = tm_subnode__get_subscribers(child, TRUE, subscribers);
        if (err) {
          return err;
        }
        break;
      }
    }
    return 0;
  }
  
  // find next topic level
  while (level[level_len] != TP_LEVEL_SEPARATOR && level[level_len] != '\0') {
    level_len++;
  }
  
  DL_FOREACH(n->children, child) {
    if (level_len == 1 && level[0] == TP_MULTI_LEVEL_WILDCARD) {
      err = tm_subnode__get_subscribers(child, TRUE, subscribers);
      if (err) {
        return err;
      }
    } else if ((level_len == 1 && level[0] == TP_SINGLE_LEVEL_WILDCARD) || strncmp(level, child->name, level_len) == 0) {
      err = tm_subnode__match(child, topic + level_len, subscribers);
      if (err) {
        return err;
      }
    }
  }
  
  return 0;
}

tm_topics_t* topics__create() {
  tm_topics_t* t = (tm_topics_t*) ts__malloc(sizeof(tm_topics_t));
  if (t == NULL) {
    return NULL;
  }
  
  ts_mutex__init(&(t->sub_mu));
  ts_error__init(&(t->err));
  
  memset(&(t->sub_root), 0, sizeof(tm_subnode_t));
  
  return t;
}
int topics__destroy(tm_topics_t* t) {
  ts_mutex__destroy(&(t->sub_mu));
  
  // TODO: free sub_root
  return 0;
}

int tm_topics__subscribe(tm_topics_t* t, const char* topic, char qos, void* subscriber) {
  int err;
  ts_mutex__lock(&(t->sub_mu));
  
  err = tm_subnode__insert(&(t->sub_root), topic, qos, subscriber);
  if (err) {
    ts_error__set(&(t->err), err);
  }
  
  ts_mutex__unlock(&(t->sub_mu));
  
  return err;
}

int tm_topics__unsubscribe(tm_topics_t* t, const char* topic, void* subscriber) {
  int err;
  ts_mutex__lock(&(t->sub_mu));
  
  
  err = tm_subnode__remove(&(t->sub_root), topic, subscriber);
  if (err) {
    ts_error__set(&(t->err), err);
  }
  
  ts_mutex__unlock(&(t->sub_mu));
  
  return err;
}

int tm_topics__subscribers(tm_topics_t* t, const char* topic, char qos, tm_subscribers_t** subscribers) {
  int err;
  ts_mutex__lock(&(t->sub_mu));
  
  
  err = tm_subnode__match(&(t->sub_root), topic, subscribers);
  if (err) {
    ts_error__set(&(t->err), err);
  }
  
  ts_mutex__unlock(&(t->sub_mu));
  
  return err;
}



static int tm_topics__valid_common(const char* topic, ts_error_t* err) {
  if (topic == NULL) {
    ts_error__set_msg(err, TS_ERR_INVALID_TOPIC, "Topic MUST be at least one character long");
    return err->err;
  }
  
  if (strlen(topic) > 65535) {
    ts_error__set_msg(err, TS_ERR_INVALID_TOPIC, "Topic MUST NOT encode to more than 65535 bytes");
    return err->err;
  }
  
  return 0;
}
int tm_topics__valid_topic_filter(const char* topic, ts_error_t* err) {
  tm_topics__valid_common(topic, err);
  if (err->err) {
    return err->err;
  }
  
  int tp_len = strlen(topic);
  
  for (int i = 0; i < tp_len; i++) {
    char c = topic[i];
    
    if (c == TP_MULTI_LEVEL_WILDCARD) {
      if (i + 1 != tp_len) {
        ts_error__set_msg(err, TS_ERR_INVALID_TOPIC, "Multi-level wildcard MUST be the last character in the topic");
        return TS_ERR_INVALID_TOPIC;
      }
      
      if (i > 0 && topic[i-1] != TP_LEVEL_SEPARATOR) {
        ts_error__set_msg(err, TS_ERR_INVALID_TOPIC, "Multi-level wildcard can only follow a topic level separator");
        return TS_ERR_INVALID_TOPIC;
      }
    } else if (c == TP_SINGLE_LEVEL_WILDCARD) {
      if ((i > 0 && topic[i-1] != TP_LEVEL_SEPARATOR) || (i + 1 < tp_len && topic[i+1] != TP_LEVEL_SEPARATOR)) {
        ts_error__set_msg(err, TS_ERR_INVALID_TOPIC, "Single-level wildcard MUST occupy an entire level of the topic filter");
        return TS_ERR_INVALID_TOPIC;
      }
    }
  }
  
  return 0;
}
int tm_topics__valid_topic_name(const char* topic, ts_error_t* err) {
  tm_topics__valid_common(topic, err);
  if (err->err) {
    return err->err;
  }
  
  for (int i = 0; i < strlen(topic); i++) {
    char c = topic[i];
    if (c == TP_MULTI_LEVEL_WILDCARD || c == TP_SINGLE_LEVEL_WILDCARD) {
      ts_error__set_msgf(err, TS_ERR_INVALID_TOPIC, "Invalid characters in the topic(%d)", c);
      return err->err;
    }
  }
  
  return 0;
}
