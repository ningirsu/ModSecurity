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

/**
 * @file
 *
 * Logs alerts to the Prelude system, using IDMEF (RFC 4765) messages
 *
 * This modules requires a Prelude profile to work (see man prelude-admin)
 * and the Prelude Handbook for help
 *
 * \author Vérène houdebine <verene.houdebine@rez-gif.supelec.fr>
 * \author Sélim Menouar <selim.menouar@rez-gif.supelec.fr>
 */


#include "modsecurity.h"
#include <sys/stat.h>

#include "re.h"
#include "idmef_logging.h"
#include "httpd.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"
#include "msc_util.h"

#include "apr_version.h"
#include <libxml/xmlversion.h>

#ifndef PRELUDE

/* Handle the case where no PRELUDE support is compiled in. */

void idmef_log(modsec_rec *msr, msre_actionset *actionset, const char *action_message, const char *rule_message){
    msr_log(msr, 1, "Can't send idmef alert : Prelude support was disabled during build (run ./configure --enable-prelude)");
}

#else /* implied we do have PRELUDE support*/

#include <libprelude/prelude.h>

#define ANALYZER_CLASS "WAF"
#define ANALYZER_MODEL "ModSecurity"
#define ANALYZER_MANUFACTURER "https://trustwave.com"
#define ANALYZER_NAME "ModSecurity"

static prelude_client_t *prelude_client;


/** \brief Setup Analyzer
 *
 * \param analyzer Analyzer to complete
 *
 * \retval 0 On Success
 */
int idmef_analyzer_setup(idmef_analyzer_t *analyzer){
    int ret;
    prelude_string_t *str;

    /* alert->analyzer->name */
    ret = idmef_analyzer_new_name(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_NAME );

    /* alert->analyzer->model */
    ret = idmef_analyzer_new_model(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MODEL );

    /* alert->analyzer->class */
    ret = idmef_analyzer_new_class(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_CLASS);

    /* alert->analyzer->manufacturer */
    ret = idmef_analyzer_new_manufacturer(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, ANALYZER_MANUFACTURER);

    /* alert->analyzer->version */
    ret = idmef_analyzer_new_version(analyzer, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_constant(str, MODSEC_VERSION);

    return 0;
}

/** \brief Initialize Prelude Client
 *
 * \param analyzer_name Name of the analyzer

 * \retval 0 On Success
 * \retval -1 On Fail
 */
int prelude_initialize_client(const char *analyzer_name){
    int ret;

    prelude_client = NULL;

    ret = prelude_init(0, NULL);
    if ( ret < 0 )  {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Unable to initialize the prelude library : %s", prelude_strerror(ret));
        return -1;
    }


    ret = prelude_client_new(&prelude_client, analyzer_name);
    if ( ret < 0 )  {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Unable to create a prelude client object : %s", prelude_strerror(ret));
        return -1;
    }

    ret = idmef_analyzer_setup(prelude_client_get_analyzer(prelude_client));
    if ( ret < 0 )  {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s", prelude_strerror(ret));
        return -1;
    }

    ret = prelude_client_start(prelude_client);
    if ( ret < 0 || ! prelude_client ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Unable to start prelude client : %s", prelude_strerror(ret));
        prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        return -1;
    }

    ret = prelude_client_set_flags(prelude_client, PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if ( ret < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Unable to sned asynchrnous send and timer : %s", prelude_strerror(ret));
        prelude_client_destroy(prelude_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        return -1;
    }

    return 0;
}

int add_string_additional_data(idmef_alert_t *alert, const char *meaning, const char *ptr){
    int ret;
    prelude_string_t *str;
    idmef_additional_data_t *ad;
    idmef_data_t *data;

    ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
    if ( ret < 0 )
        return ret;

    idmef_additional_data_set_type(ad, IDMEF_ADDITIONAL_DATA_TYPE_STRING);

    idmef_additional_data_new_data(ad, &data);

    ret = idmef_data_set_char_string_ref(data, ptr);
    if ( ret < 0)
        return ret;


    ret = idmef_additional_data_new_meaning(ad, &str);
    if ( ret < 0)
        return ret;

    ret = prelude_string_set_ref(str, meaning);
    if ( ret < 0 )
        return ret;

    return 0;
}

int idmef_set_additional_data(idmef_alert_t *alert, modsec_rec *msr){
    int ret;
    int i;
    const apr_array_header_t *tarr;
    const apr_table_entry_t *telts;

    /* alert->additional_data->request_header */
    tarr = apr_table_elts(msr->request_headers);
    telts = (const apr_table_entry_t*) tarr->elts;

    for (i = 0; i < tarr->nelts; i++) {
        ret = add_string_additional_data(alert, telts[i].key, telts[i].val);
        if ( ret < 0)
            return ret;
    }
}

int idmef_set_severity(idmef_assessment_t *assessment, int severity){
    int ret;
    idmef_impact_t *impact;

    ret = idmef_assessment_new_impact(assessment, &impact);
    if ( ret < 0 )
        return ret;

    if (severity == 0)
        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_HIGH);
    else if (severity < 3)
        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_MEDIUM);
    else if (severity < 6)
        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_LOW);
    else
        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_INFO);

    return 0;
}

int idmef_set_accuracy(idmef_assessment_t *assessment, int accuracy){
    int ret;
    idmef_confidence_t *confidence;

    ret = idmef_assessment_new_confidence(assessment, &confidence);
    if ( ret < 0 )
        return ret;

    if(accuracy <4)
        idmef_confidence_set_rating(confidence, IDMEF_CONFIDENCE_RATING_LOW);
    else if(accuracy<7)
        idmef_confidence_set_rating(confidence, IDMEF_CONFIDENCE_RATING_MEDIUM);
    else
        idmef_confidence_set_rating(confidence, IDMEF_CONFIDENCE_RATING_HIGH);

    return 0;
}

int idmef_set_target_node(idmef_target_t *target, modsec_rec *msr){
    int ret;
    idmef_node_t *nodet;
    idmef_address_t *addresst;
    prelude_string_t *str;

    ret = idmef_target_new_node(target, &nodet);
    if ( ret < 0 )
        return ret;

    /* alert->target->node->address */
    ret = idmef_node_new_address(nodet, &addresst, 0);
    if ( ret < 0 )
        return ret;

    ret = idmef_address_new_address(addresst, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_ref(str, msr->local_addr);
    idmef_address_set_category(addresst, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);

    /* alert->target->node->name */
    ret = idmef_node_new_name(nodet, &str);
    if ( ret < 0 )
        return ret;

    prelude_string_set_ref(str, msr->hostname);
    idmef_node_set_category(nodet, IDMEF_NODE_CATEGORY_DNS);

    return 0;
}

int idmef_set_source_node(idmef_source_t *source, modsec_rec *msr){
    int ret;
    prelude_string_t *str;
    idmef_node_t *nodes;
    idmef_address_t *addresss;

    ret = idmef_source_new_node(source, &nodes);
    if ( ret < 0 )
        return ret;

    /* alert->source->node->address */
    ret = idmef_node_new_address(nodes, &addresss, 0);
    if ( ret < 0 )
        return ret;

    ret = idmef_address_new_address(addresss, &str);
    if ( ret < 0 )
        return ret;

    idmef_address_set_category(addresss, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);
    prelude_string_set_ref(str, msr->remote_addr);

    return 0;
}

int idmef_set_alert_assessment(idmef_alert_t *alert, modsec_rec *msr, msre_actionset *actionset){
    int ret;
    prelude_string_t *str;
    idmef_assessment_t *assessment;

    ret = idmef_alert_new_assessment(alert, &assessment);
    if ( ret < 0)
        return ret;

    /* alert->assessment->severity */
    ret = idmef_set_severity(assessment, actionset->severity);
    if ( ret < 0)
        return ret;

    /* alert->assessment->confidence */
    ret = idmef_set_accuracy(assessment, actionset->accuracy);
    if ( ret < 0)
        return ret;

    return 0;
}

int idmef_set_target_service(idmef_target_t *target, modsec_rec *msr){
    int ret;
    prelude_string_t *str;
    idmef_service_t *servicet;

    ret = idmef_target_new_service(target, &servicet);
    if ( ret < 0)
        return ret;

    /* alert->target->service->port */
    idmef_service_set_port(servicet, msr->local_port);

    /* alert->target->service->protocol */
    ret = idmef_service_new_protocol(servicet, &str);
    if ( ret < 0)
        return ret;

    prelude_string_set_ref(str, msr->request_protocol);

    ret = idmef_set_target_webservice(servicet, msr);
    if ( ret < 0)
        return ret;

    return 0;
}

int idmef_set_target_webservice(idmef_service_t *servicet, modsec_rec *msr){
    int ret;
    prelude_string_t *str;
    idmef_web_service_t *webservicet;
    const apr_array_header_t *tarr;
    const apr_table_entry_t *telts;
    const msc_arg *arg;
    int i;

    /* alert->target->service->webservice->uri */
    ret = idmef_service_new_web_service(servicet, &webservicet);
    if ( ret < 0)
        return ret;

    ret = idmef_web_service_new_url(webservicet, &str);
    if ( ret < 0)
        return ret;

    prelude_string_set_ref(str, msr->request_uri);

    /* alert->target->service->webservice->reques-method */
    ret = idmef_web_service_new_http_method(webservicet, &str);
    if ( ret < 0)
        return ret;

    prelude_string_set_ref(str, msr->request_method);

    /* alert->target->service->webservice->arg */
    tarr = apr_table_elts(msr->arguments);
    telts = (const apr_table_entry_t*) tarr->elts;

    for (i = 0; i < tarr->nelts; i++) {
        arg = (const msc_arg *)telts[i].val;
        ret = idmef_web_service_new_arg(webservicet, &str, IDMEF_LIST_APPEND);
        if ( ret < 0)
            return ret;
        prelude_string_set_ref(str, arg->value);
    }

    return 0;
}

int idmef_set_source_service(idmef_source_t *source, modsec_rec *msr){
    int ret;
    prelude_string_t *str;
    idmef_service_t *services;

    ret = idmef_source_new_service(source, &services);
    if ( ret < 0)
        return ret;

    /* alert->source->service->port */
    idmef_service_set_port(services,msr->remote_port);

    /* alert->source>service->protocol */
    ret = idmef_service_new_protocol(services, &str);
    if ( ret < 0)
        return ret;

    prelude_string_set_ref(str, msr->response_protocol);

    return 0;
}

int idmef_set_target_process(idmef_target_t *target, modsec_rec *msr){
    int ret;
    prelude_string_t *str;
    idmef_process_t *processt;

    ret = idmef_target_new_process(target, &processt);
    if ( ret < 0)
        return ret;

    /* alert->target->process->name */
    ret = idmef_process_new_name(processt, &str);
    if ( ret < 0)
        return ret;

    prelude_string_set_ref(str, msr->server_software);

    /* alert->target->process->pid */
    idmef_process_set_pid(processt, (int)getpid());

    return 0;
}

/** \brief Send an alert to a prelude-manager
 *
 * \param msr
 * \param actionset
 * \param action_message
 * \param rule_message

 */
void idmef_log(modsec_rec *msr, msre_actionset *actionset, const char *action_message, const char *rule_message){
    int ret;
    idmef_message_t *idmef = NULL;
    idmef_alert_t *alert;
    idmef_classification_t *class;
    prelude_string_t *str;
    idmef_target_t *target;
    idmef_source_t *source;
    idmef_file_t *file;

    ret = idmef_message_new(&idmef);
    if ( ret < 0 )
        goto err;

    ret = idmef_message_new_alert(idmef, &alert);
    if ( ret < 0 )
        goto err;

    /* alert->classification */
    ret = idmef_alert_new_classification(alert, &class);
    if ( ret < 0 )
        goto err;

    ret = idmef_classification_new_text(class, &str);
    if ( ret < 0 )
        goto err;

    prelude_string_set_ref(str, actionset->msg);

    ret = idmef_classification_new_ident(class, &str);
    if ( ret < 0 )
        goto err;

    prelude_string_set_ref(str, actionset->id);

    /* alert->assessment */
    ret = idmef_set_alert_assessment(alert, msr, actionset);
    if ( ret < 0 )
        goto err;

    /* alert->messageid */
    ret = idmef_alert_new_messageid(alert, &str);
    if ( ret < 0 )
        goto err;

    prelude_string_set_ref(str, msr->txid);

    /* alert->target->node */
    ret = idmef_alert_new_target(alert, &target, 0);
    if ( ret < 0 )
        goto err;

    ret = idmef_set_target_node(target,msr);
    if ( ret < 0 )
        goto err;

    /* alert->source->node */
    ret = idmef_alert_new_source(alert, &source, 0);
    if ( ret < 0 )
        goto err;

    ret = idmef_set_source_node(source, msr);
    if ( ret < 0 )
        goto err;

    /* alert->target->service */
    ret = idmef_set_target_service(target, msr);
    if ( ret < 0 )
        goto err;

    /* alert->source->service */
    ret = idmef_set_source_service(source, msr);
    if ( ret < 0 )
        goto err;

    /* alert->target->process */
    ret = idmef_set_target_process(target, msr);
    if ( ret < 0 )
        goto err;

    ret = add_string_additional_data(alert, "Action message", action_message);
    if ( ret < 0 )
        goto err;

    ret = add_string_additional_data(alert, "Rule message", rule_message);
    if ( ret < 0 )
        goto err;

    if ( msr->multipart_filename != NULL ){
        ret = idmef_target_new_file(target, &file, 0);
        if ( ret < 0 )
            goto err;

        ret = idmef_file_new_name(file, &str);
        if ( ret < 0 )
            goto err;

        prelude_string_set_ref(str, msr->multipart_filename);
    }

    ret = idmef_set_additional_data(alert, msr);
    if ( ret < 0 )
        goto err;

    if ( prelude_client == NULL )
        prelude_initialize_client(msr->txcfg->analyzer_name);

    prelude_client_send_idmef(prelude_client, idmef);
    idmef_message_destroy(idmef);

    return;

err:
    if (idmef != NULL)
        idmef_message_destroy(idmef);

    msr_log(msr, 1, "%s error: %s", prelude_strsource(ret), prelude_strerror(ret));
    return;
}
#endif /* PRELUDE */

