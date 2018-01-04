/*
 *
 * Copyright (c) 2018 Nest Labs, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __wpantund__Log_h__
#define __wpantund__Log_h__

#if 0

#include <syslog.h>

#else

#define syslog(priority, format, ...)
#define openlog(...)

#define setlogmask(mask) 0
#define LOG_FAC(mask)    mask
#define LOG_MASK(mask)   mask



#define LOG_EMERG        0
#define LOG_ALERT        1
#define LOG_CRIT         2
#define LOG_ERR          3
#define LOG_WARNING      4
#define LOG_NOTICE       5
#define LOG_INFO         6
#define LOG_DEBUG        7

#define LOG_DAEMON       3
#define LOG_USER         1

#endif

#endif /* defined(__wpantund__Log_h__) */
