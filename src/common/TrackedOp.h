// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2012 New Dream Network/Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */
#ifndef TRACKEDREQUEST_H_
#define TRACKEDREQUEST_H_

#include "include/int_types.h"

#include <sstream>
#include <tr1/memory>

#include "include/utime.h"
#include "include/xlist.h"
#include "common/Mutex.h"
#include "msg/Message.h"

class TrackedOp {
public:
  virtual void mark_event(const string &event) = 0;
  virtual ~TrackedOp() {}
};
typedef std::tr1::shared_ptr<TrackedOp> TrackedOpRef;

#endif
