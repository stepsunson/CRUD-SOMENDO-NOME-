// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

struct config {
  int tunnel_ifindex;
};
BPF_HASH(conf, int, struct config, 1);

struct tunnel_key {
  u32 tunnel_id;
  u32 remote_ipv4;
};
BPF_HASH(tunkey2if, struct tunnel_key, int, 1024);

BPF_HASH(if2tunkey, int, struct tu