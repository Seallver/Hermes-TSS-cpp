#include "struct.pb.switch.h"

#include <google/protobuf/port_def.inc>

#if PROTOBUF_VERSION >= 3014000 && 3014000 >= PROTOBUF_MIN_PROTOC_VERSION
#include <google/protobuf/port_undef.inc>
#include "3_14/struct.pb.cc"
#elif PROTOBUF_VERSION >= 3020000 && 3020000 >= PROTOBUF_MIN_PROTOC_VERSION
#include <google/protobuf/port_undef.inc>
#include "3_20/struct.pb.cc"
#else
#error Invalid version of protobuf.
#endif
