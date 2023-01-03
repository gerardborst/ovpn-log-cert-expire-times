#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "openvpn-plugin.h"
#include "x509.h"

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#define PLUGIN_NAME "log-cert-expire-times"

#define TIME_SIZE 50

/* Where we store our own settings/state */
struct plugin_context
{
    plugin_log_t plugin_log;
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *retptr)
{
    plugin_log_t log = args->callbacks->plugin_log;
    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

    struct plugin_context *context = NULL;

    /* Safeguard on openvpn versions */
    if (v3structver < OPENVPN_PLUGINv3_STRUCTVER)
    {
        log(PLOG_ERR, PLUGIN_NAME,
            "ERROR: struct version was older than required");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (args->ssl_api != SSLAPI_OPENSSL)
    {
        log(PLOG_ERR, PLUGIN_NAME, "This plug-in can only be used against OpenVPN with OpenSSL");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    log(PLOG_NOTE, PLUGIN_NAME, "Version: [%s]", STRINGIZE_VALUE_OF(VERSION));
    log(PLOG_NOTE, PLUGIN_NAME, "Commit Hash: [%s]", STRINGIZE_VALUE_OF(COMMIT_HASH));
    log(PLOG_NOTE, PLUGIN_NAME, "Build Time: [%s]", STRINGIZE_VALUE_OF(BUILD_TIME));
    log(PLOG_NOTE, PLUGIN_NAME, "Compile Type: [%s]", STRINGIZE_VALUE_OF(COMPILE_TYPE));

    /*  Which callbacks to intercept.  */
    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TLS_VERIFY);

    /* create context */
    context = (struct plugin_context *)malloc(sizeof(struct plugin_context));
    memset(context, 0, sizeof(struct plugin_context));

    context->plugin_log = log;

    /* Pass state back to OpenVPN so we get handed it back later */
    retptr->handle = (openvpn_plugin_handle_t)context;

    log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static void
x509_print_info(X509 *x509crt, const char *common_name, plugin_log_t log)
{
    struct tm tm;
    char time_buffer[TIME_SIZE];

    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: x509_print_info");
    log(PLOG_DEBUG, PLUGIN_NAME, "CN: [%s]", common_name);

    const ASN1_TIME *not_after_time = X509_get0_notAfter(x509crt);
    if (!not_after_time)
    {
        log(PLOG_ERR, PLUGIN_NAME, "[not_after_time] is null");
        return;
    }

    // write not after time to log
    if (!ASN1_TIME_to_tm(not_after_time, &tm))
    {
    	log(PLOG_ERR, PLUGIN_NAME, "Error converting [not_after_time] to time");
        return;
    }

    // Feb 26 21:11:08 2023 GMT
    strftime(time_buffer, TIME_SIZE, "%b %e %H:%M:%S %Y %Z", &tm);

    log(PLOG_NOTE, PLUGIN_NAME, "Certificate of: user, not after |%s,%s|", common_name, time_buffer);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *retptr)
{
    struct plugin_context *context =
        (struct plugin_context *)args->handle;
    plugin_log_t log = context->plugin_log;

    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_func_v3");
    log(PLOG_DEBUG, PLUGIN_NAME, "TLS Cerificate [%s]", args->current_cert ? "available" : "not available");

    if ((args->type == OPENVPN_PLUGIN_TLS_VERIFY) && args->current_cert)
    {
    	log(PLOG_DEBUG, PLUGIN_NAME, "Certificate Depth: [%i]", args->current_cert_depth);

    	if (args->current_cert_depth == 0)
        {
            const char *common_name = get_env("X509_0_CN", args->envp);

            x509_print_info(args->current_cert, common_name, log);
        }
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *)handle;
    context->plugin_log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_close_v1");
    free(context);
}
