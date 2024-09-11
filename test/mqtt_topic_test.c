#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include <mqtt_topics.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

TEST_IMPL(mqtt_valid_topic_name_test) {
  char* valid_topics[] = {
      "sport/tennis/player1",
      "sport/tennis/player1/ranking",
      "sport/tennis/player1/score/wimbledon",
      "sport",
      "/finance",
      "/              a",
      " ",
      "/",
      "sport/"
  };
  
  ts_error_t err;
  ts_error__init(&err);
  
  for (int i = 0; i < ARRAY_SIZE(valid_topics); i++) {
    tm_topics__valid_topic_name(valid_topics[i], &err);
    ASSERT_EQ(err.err, 0);
  }
  return 0;
}
TEST_IMPL(mqtt_valid_topic_filter_test) {
  char* valid_topics[] = {
      "sport/tennis/player1/#",
      "sport/#",
      "#",
      "sport/tennis/#",
      "+",
      "+/tennis/#",
      "sport/+/player1",
      "+/+",
      "/+",
      "/  a",
      " ",
      "/",
      "sport/tennis/+",
      "sport/"
  };
  
  ts_error_t err;
  ts_error__init(&err);
  
  for (int i = 0; i < ARRAY_SIZE(valid_topics); i++) {
    tm_topics__valid_topic_filter(valid_topics[i], &err);
    ASSERT_EQ(err.err, 0);
  }
  return 0;
}
TEST_IMPL(mqtt_invalid_topic_name_test) {
  char* invalid_topics[] = {
      "#",
      "+",
      "",
      "a/b/#",
      "a/+"
  };
  ts_error_t err;
  ts_error__init(&err);
  
  for (int i = 0; i < ARRAY_SIZE(invalid_topics); i++) {
    tm_topics__valid_topic_name(invalid_topics[i], &err);
    ASSERT_NE(err.err, 0);
    ts_error__reset(&err);
  }
  return 0;
}
TEST_IMPL(mqtt_invalid_topic_filter_test) {
  char* invalid_topics[] = {
      "sport/tennis#",
      "sport/tennis/#/ranking",
      "sport+",
      "",
  };
  
  ts_error_t err;
  ts_error__init(&err);
  
  for (int i = 0; i < ARRAY_SIZE(invalid_topics); i++) {
    tm_topics__valid_topic_filter(invalid_topics[i], &err);
    ASSERT_NE(err.err, 0);
    ts_error__reset(&err);
  }
  return 0;
}



