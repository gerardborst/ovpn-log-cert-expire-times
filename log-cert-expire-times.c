#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openvpn-plugin.h"
#include "x509.h"

#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)

#define PLUGIN_NAME "log-cert-expire-times"

/* Where we store our own settings/state */
struct plugin_context
{
    plugin_log_t plugin_log;
    const char *output_filename;
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

    /*
     *
     * Note that if arg_size is 0 no script argument was included.
     */
    if (!(args->argv[1]))
    {
        log(PLOG_ERR, PLUGIN_NAME, "no output_filename argument on plugin in openvpn config file");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /*
     * Plugin init will fail unless we create a handler, so we'll store our
     * script path and it's arguments there as we have to create it anyway.
     */
    context = (struct plugin_context *)malloc(
        sizeof(struct plugin_context) + strlen(args->argv[1]));
    memset(context, 0, sizeof(struct plugin_context));
    memcpy(&context->output_filename, &args->argv[1], strlen(args->argv[1]));

    context->plugin_log = log;

    log(PLOG_NOTE, PLUGIN_NAME,
        "output_filename=%s",
        context->output_filename);

    /* Pass state back to OpenVPN so we get handed it back later */
    retptr->handle = (openvpn_plugin_handle_t)context;

    log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static void
x509_print_info(X509 *x509crt, const char *common_name, const char *filename, plugin_log_t log)
{
    log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: x509_print_info");
    log(PLOG_DEBUG, PLUGIN_NAME, "CN: [%s] Filename: [%s]", common_name, filename);

    const ASN1_TIME *not_after_time = X509_get0_notAfter(x509crt);

    if (!not_after_time)
    {
        log(PLOG_ERR, PLUGIN_NAME, "[not_after_time] is null");
        return;
    }

    BIO *out;
    out = BIO_new_file(filename, "a");
    if (!out)
    {
    	log(PLOG_ERR, PLUGIN_NAME, "Error opening file [%s]", filename);
        return;
    }

    // write CN to file
    BIO_printf(out, "%s,", common_name);
    // write not after time to log
    if (!ASN1_TIME_print(out, not_after_time))
    {
    	log(PLOG_ERR, PLUGIN_NAME, "Error writing time [not_after_time] to file [%s]", filename);
            return;
    }
    BIO_printf(out, "\n");

    BIO_free(out);
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
            const char *output_filename = context->output_filename;

            x509_print_info(args->current_cert, common_name, output_filename, log);
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
