/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include "modsecurity.h"
#include "re.h"

#ifndef __IDMEF_LOGGING_H_
#define __IDMEF_LOGGING_H_

#endif

void DSOLOCAL idmef_log(modsec_rec *msr, msre_actionset *actionset, const char *action_message, const char *rule_message);

