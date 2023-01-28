#include <stdlib.h>
#include <esp_log.h>
#include <sys/socket.h>
#include <map>
#include "esp_http_server.h"
#include "esp_event.h"
#include "sdkconfig.h"
#include "pp.h"
#include "webserver.h"
#include "math.h"
#include "ethernet.h"
#include "esp_spiffs.h"
#include "cjson.h"

#define MIN(a, b) ((a) > (b) ? (b) : (a))
#define RECV_BUFFER_SIZE 1024
#define TWO_PI 6.28318530
#define MAX_FLOAT_BYTES 80

static const char *hdr_discovery_begin = "<h3>MASI - Discovery</h3><table>";
static const char *hdr_table_end = "</table>";
static const char *hdr_public_var_begin = "<h3>MASI - Public Variables</h3><table>";

static const char *TAG = "WEBSERVER";
static const char *SUBSCRIBE_RESP = "subscribeResp";
static const char *RESP_MESSAGE = "{\"cmd\":\"%s\",\"data\":{\"name\":\"%s\", \"value\":";
static const char *NEWSTATE_FLOAT = "{\"cmd\":\"newState\",\"data\":{\"name\":\"%s\", \"value\":%f}}";
static const char *NEWSTATE_FLOAT_ARRAY = "{\"cmd\":\"newState\",\"data\":{\"name\":\"%s\", \"value\":\"float\"}}";
static const char *UNSUBSCRIBE_MESSAGE = "{\"cmd\":\"unsubscribeResp\",\"data\":\"%s\"}";

static pp_t pp_wsdata;
static httpd_handle_t server = NULL;
static int open_sockets = 0;
static std::map<int32_t, pp_webclient_t> subscribtion_web;
static pp_evloop_t myloop;
static esp_event_base_t EV_BASE = "WEBSERVER_BASE";

extern esp_err_t get_handler(httpd_req_t *req);

/*
static void print_web_clients(httpd_req_t *req, char *buf, size_t bufsize)
{
    httpd_resp_send_chunk(req, "<h3>MASI - Web Subscriptions</h3><table>", HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, "<tr><th>Web subscriptions</th><td>%d</td></tr>", subscribtion_web.size());
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, "<tr><th>Open Sockets</th><td>%d</td></tr>", open_sockets);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);
}

static void print_hanning(httpd_req_t *req, char *buf, size_t bufsize, size_t size)
{
    float pi = 3.14159265359;
    snprintf(buf, bufsize, "const float hanning_window[%d] = {", size);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    for (int i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            httpd_resp_send_chunk(req, "<br>", HTTPD_RESP_USE_STRLEN);
        snprintf(buf, bufsize, "%f,", pow(sin(pi * i / size), 2));
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    }

    snprintf(buf, bufsize, "};");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
}

static void print_twiddle_factors(httpd_req_t *req, char *buf, size_t bufsize, size_t factor_count)
{
    float two_pi_by_n = TWO_PI / factor_count;

    snprintf(buf, bufsize, "const float twiddle_factors[%d] = {\n", factor_count);
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);

    for (int k = 0, m = 0; k < factor_count; k++, m += 2)
    {
        snprintf(buf, bufsize, "%f,%f,", cosf(two_pi_by_n * k), sinf(two_pi_by_n * k));
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
        if (k % 10 == 0)
            httpd_resp_send_chunk(req, "<br>", HTTPD_RESP_USE_STRLEN);
    }

    snprintf(buf, bufsize, "};\n");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
}
*/
bool pp_print_parameter(int index, char *buf, size_t bufsize)
{
    pp_t pp = pp_get_par(index);
    if (pp == NULL)
        return false;

    const char *str = "--";
    const char *name = pp_get_name(pp);
    pp_evloop_t *owner = pp_get_owner(pp);
    int subscriptions = pp_get_subscriptions(pp);
    void *valueptr = pp_get_valueptr(pp);

    switch (pp_get_type(pp))
    {
    case TYPE_FLOAT:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%f</td><td>%s</td></tr>",
                 index, "Float", name, owner ? owner->base : str, subscriptions, valueptr != NULL ? *((float *)valueptr) : 0, pp_unit_to_str(pp_get_unit(pp)));
        break;
    case TYPE_INT16_ARRAY:
    case TYPE_FLOAT_ARRAY:
    case TYPE_EXECUTE:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td></td><td></td></tr>",
                 index, "Float[]", name, owner ? owner->base : str, subscriptions);
        break;
    case TYPE_STRING:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>String</td><td>%s</td><td>%s</td><td>%d</td><td>--</td><td></td></tr>",
                 index, name, owner ? owner->base : str, subscriptions);
        break;
    case TYPE_BINARY:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>--</td><td></td></tr>",
                 index, "Binary", name, owner ? owner->base : str, subscriptions);
        break;
    case TYPE_BOOL:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>--</td><td>--</td><td></td></tr>",
                 index, "Bool", name, owner ? owner->base : str);
        break;
    default:
        snprintf(buf, bufsize, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>--</td><td>--</td><td></td></tr>",
                 index, "Unknown", name, owner ? owner->base : str);
        break;
    }
    return true;
}

/*
static void print_public_parameters(httpd_req_t *req, char *buf, size_t bufsize)
{
    int index = 0;
    const char *pp_header = "<tr><th>Nr.</th><th>Type</th><th>Name</th><th>Owner</th><th>Subscriptions</th><th>Value</th><th>Unit</th></tr>";
    httpd_resp_send_chunk(req, hdr_public_var_begin, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, pp_header, HTTPD_RESP_USE_STRLEN);
    bool ok = pp_print_parameter(index, buf, bufsize);
    while (ok)
    {
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
        index++;
        ok = pp_print_parameter(index, buf, bufsize);
    }
    httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);
}

static void print_discovery(httpd_req_t *req, char *buf, size_t bufsize)
{
    static const char *if_str[] = {"STA", "AP", "ETH", "MAX"};
    static const char *ip_protocol_str[] = {"V4", "V6", "MAX"};
    char ipstr[128];
    char txt[128];
    httpd_resp_send_chunk(req, hdr_discovery_begin, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, "<tr> <th>Interface</th> <th>Type</th> <th>TTL</th> <th>Instance Name</th> <th>Service Type</th><th>Protocol</th> <th>Hostname</th> <th>Port</th> <th>IP</th> <th>TXT Record</th></tr>");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    mdns_result_t *r = discovery_run_query();
    mdns_ip_addr_t *a = NULL;

    while (r)
    {
        a = r->addr;
        int len = 0;
        while (a)
        {
            if (a->addr.type == ESP_IPADDR_TYPE_V6)
                len += snprintf(&ipstr[len], 128 - len, IPV6STR "<br>", IPV62STR(a->addr.u_addr.ip6));
            else
                len += snprintf(&ipstr[len], 128 - len, IPSTR "<br>", IP2STR(&(a->addr.u_addr.ip4)));
            a = a->next;
        }

        if (r->txt_count)
        {
            int t;
            len = 0;
            for (t = 0; t < r->txt_count; t++)
                len += snprintf(&txt[len], 128 - len, "%s=%s(%d)<br>", r->txt[t].key, r->txt[t].value ? r->txt[t].value : "NULL", r->txt_value_len[t]);
        }

        snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>%u</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%u</td><td>%s</td><td>%s</td>",
                 if_str[r->tcpip_if],
                 ip_protocol_str[r->ip_protocol],
                 r->ttl,
                 r->instance_name,
                 r->service_type,
                 r->proto,
                 r->hostname,
                 r->port,
                 ipstr,
                 txt);
        r = r->next;
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    }
    mdns_query_results_free(r);
    httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);
}
*/
/*static size_t tojson_string(void *inp, char *outp_json, size_t json_size)
{
    size_t used = 0;
    if (outp_json == NULL)
        ESP_LOGE(TAG, "%s: outp_json is NULL", __func__);
    else if (json_size == 0)
        ESP_LOGE(TAG, "%s: json_size is NULL", __func__);
    else
    {
        const char *str = (const char *)inp;
        if (str == NULL)
            str = "\"\"";
        used = snprintf(outp_json, json_size, "%s", str);
    }
    return used;
}

static size_t tojson_bool(void *inp, char *outp_json, size_t json_size)
{
    size_t used = 0;
    if (outp_json == NULL)
        ESP_LOGE(TAG, "%s: outp_json is NULL", __func__);
    else if (json_size == 0)
        ESP_LOGE(TAG, "%s: json_size is NULL", __func__);
    else if (inp == NULL)
        ESP_LOGE(TAG, "%s: inp is NULL", __func__);
    else
        used = snprintf(outp_json, json_size, "%s", *((bool *)inp) ? "true" : "false");
    return used;
}

static size_t tojson_float(void *inp, char *outp_json, size_t json_size)
{
    size_t used = 0;
    if (outp_json == NULL)
        ESP_LOGE(TAG, "%s: outp_json is NULL", __func__);
    else if (json_size == 0)
        ESP_LOGE(TAG, "%s: json_size is NULL", __func__);
    else if (inp == NULL)
        ESP_LOGE(TAG, "%s: inp is NULL", __func__);
    else
        used = snprintf(outp_json, json_size, "%f", *((float *)inp));
    return used;
}*/

bool socket_block(int fd, bool blocking)
{
    if (fd < 0)
        return false;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
}

esp_err_t get_web(httpd_req_t *req)
{
    int read = 0;
    const int bufsize = 1024;
    char *buf = (char *)calloc(bufsize, sizeof(char));
    snprintf(buf, bufsize, "/spiffs%s", req->uri);
    FILE *file = fopen(buf, "r");
    if (file == NULL)
        ESP_LOGE(TAG, "File %s does not exist!", buf);
    else
    {
        while ((read = fread(buf, 1, bufsize, file)) > 0)
        {
            httpd_resp_send_chunk(req, buf, read);
        }
        httpd_resp_set_hdr(req, "Connection", "close");
        httpd_resp_send_chunk(req, buf, 0);
        fclose(file);
    }
    free(buf);
    return ESP_OK;
}

static bool webserver_ws_send(httpd_handle_t hd, int socket, char *data)
{
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = (uint8_t *)data;
    ws_pkt.len = strlen(data);
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    return (ESP_OK == httpd_ws_send_frame_async(hd, socket, &ws_pkt));
}

extern "C" esp_err_t httpd_ws_send_frame_async2(httpd_handle_t hd, int fd, httpd_ws_frame_t *frame, void *data, size_t data_len);

static bool webserver_ws_send_binary(httpd_handle_t hd, int socket, void *str, size_t str_len, void *bin, size_t bin_len)
{
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = (uint8_t *)str;
    ws_pkt.len = str_len + bin_len;
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;

    return (ESP_OK == httpd_ws_send_frame_async2(hd, socket, &ws_pkt, bin, bin_len));
}

static void send_string_to_web_clients(pp_t pp, char *json)
{
    for (auto it = subscribtion_web.begin(); it != subscribtion_web.end();)
    {
        if (false == webserver_ws_send(it->second.hd, it->second.socket, json))
            subscribtion_web.erase(it++);
        else
            it++;
    }
}

static bool web_post_newstate_float(pp_t pp, float f)
{
    if (subscribtion_web.size() > 0)
    {
        const char *name = pp_get_name(pp);
        size_t len = strlen(NEWSTATE_FLOAT) + strlen(name) + MAX_FLOAT_BYTES;
        char *json = (char *)malloc(len);
        snprintf(json, len, NEWSTATE_FLOAT, name, f);
        send_string_to_web_clients(pp, json);
        free(json);
    }
    return true;
}

static bool web_post_newstate_float_array(pp_t pp, pp_float_array_t *fsrc)
{
    if (subscribtion_web.size() > 0)
    {
        const char *name = pp_get_name(pp);
        size_t len = strlen(NEWSTATE_FLOAT_ARRAY) + strlen(name) + 5; // +5: null term and extra float
        char *json = (char *)calloc(1, len);
        len = snprintf(json, len, NEWSTATE_FLOAT_ARRAY, name) + 1;
        if (len / 4 * 4 != len)
            len = (len + 4) / 4 * 4;
        for (auto it = subscribtion_web.begin(); it != subscribtion_web.end();)
        {
            if (false == webserver_ws_send_binary(it->second.hd, it->second.socket, json, len, fsrc->data, fsrc->len * sizeof(float)))
                subscribtion_web.erase(it++);
            else
                it++;
        }
        free(json);
    }
    return true;
}

#define JSON_BUF_SIZE (512 * 3)
static char json_buf[JSON_BUF_SIZE];
static void create_json(pp_t pp, void *context, const char *format, ...)
{
    memset(json_buf, 0, JSON_BUF_SIZE);

    va_list valist;
    va_start(valist, format);
    int len = vsnprintf(json_buf, JSON_BUF_SIZE, format, valist);
    if (len < 0)
    {
        ESP_LOGE(TAG, "%s: Error, vsnprintf return negative", __func__);
        return;
    }
    va_end(valist);
    tojson_cb_t tojson = pp_get_tojson(pp);
    if (tojson != NULL)
    {
        size_t used = tojson(context, &json_buf[len], JSON_BUF_SIZE - len);
        strncat(json_buf, "}}", JSON_BUF_SIZE - len - used);
    }
    else
        strncat(json_buf, "\"\"}}", JSON_BUF_SIZE - len);
}

static void evloop_newstate(void *handler_arg, esp_event_base_t base, int32_t id, void *context)
{
    pp_t pp = (pp_t)handler_arg;
    parameter_type_t type = pp_get_type(pp);
    switch (type)
    {
    case TYPE_FLOAT:
        web_post_newstate_float(pp, *((float *)context));
        break;
    case TYPE_FLOAT_ARRAY:
        web_post_newstate_float_array(pp, ((pp_float_array_t *)context));
        break;
    default:
        ESP_LOGW(TAG, "unsupported type %d", type);
        break;
    }
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    // ESP_LOGI(TAG, "%s: method is %d", __func__, req->method);

    if (req->method == HTTP_GET)
        return ESP_OK;

    uint8_t receive_buffer[RECV_BUFFER_SIZE];
    memset(receive_buffer, 0, RECV_BUFFER_SIZE);
    pp_websocket_data_t *wsdata = (pp_websocket_data_t *)receive_buffer;
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    ws_pkt.payload = (uint8_t *)wsdata->payload;
    ESP_ERROR_CHECK(httpd_ws_recv_frame(req, &ws_pkt, RECV_BUFFER_SIZE - 1 - sizeof(pp_websocket_data_t)));
    ws_pkt.payload[ws_pkt.len] = 0;
    wsdata->client.hd = req->handle;
    wsdata->client.socket = httpd_req_to_sockfd(req);

    cJSON *doc = cJSON_Parse(wsdata->payload);
    if (doc == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            ESP_LOGE(TAG, "cJSON error : %s", error_ptr);
        }
        return ESP_OK;
    }

    const cJSON *cmd = cJSON_GetObjectItemCaseSensitive(doc, "cmd");
    if (!cJSON_IsString(cmd) || cmd->valuestring == NULL)
        goto exit;

    if (0 == strcmp(cmd->valuestring, "publish"))
    {
        const cJSON *data = cJSON_GetObjectItemCaseSensitive(doc, "data");
        if (!cJSON_IsObject(data))
            goto exit;

        const cJSON *name = cJSON_GetObjectItemCaseSensitive(data, "name");
        if (!cJSON_IsString(name) || name->valuestring == NULL)
            goto exit;

        pp_t pp = pp_get(name->valuestring);
        if (pp == NULL)
            goto exit;

        const cJSON *value = cJSON_GetObjectItemCaseSensitive(data, "value");

        parameter_type_t pp_type = pp_get_type(pp);
        switch (pp_type)
        {
        case TYPE_STRING:
            if (cJSON_IsString(value) && value->valuestring != NULL)
                pp_post_write_string(pp, value->valuestring);
            else
                ESP_LOGW(TAG, "%s: Parameter %s is not string", __func__, pp_get_name(pp));
            break;
        case TYPE_BOOL:
            if (cJSON_IsNumber(value))
                pp_post_write_bool(pp, value->valueint != 0);
            else
                ESP_LOGW(TAG, "%s: Parameter %s is not bool", __func__, pp_get_name(pp));
            break;
        case TYPE_FLOAT:
            if (cJSON_IsNumber(value))
                pp_post_write_float(pp, value->valuedouble);
            else
                ESP_LOGW(TAG, "%s: Parameter %s is not float", __func__, pp_get_name(pp));
            break;
        default:
            ESP_LOGE(TAG, "Publish for parameter %s of type %d not supported", pp_get_name(pp), pp_type);
            break;
        }
    }
    else
    {
        const cJSON *parname = cJSON_GetObjectItemCaseSensitive(doc, "data");
        if (!cJSON_IsString(parname) || parname->valuestring == NULL)
            goto exit;

        pp_t pp = pp_get(parname->valuestring);
        if (pp == NULL)
            goto exit;

        if (0 == strcmp(cmd->valuestring, "subscribe"))
        {
            pp_subscribe(pp, &myloop, evloop_newstate);
            create_json(pp, pp_get_valueptr(pp), RESP_MESSAGE, SUBSCRIBE_RESP, parname->valuestring);

            if (webserver_ws_send(wsdata->client.hd, wsdata->client.socket, json_buf))
                subscribtion_web[wsdata->client.socket] = wsdata->client;
        }
        else if (0 == strcmp(cmd->valuestring, "unsubscribe"))
        {
            pp_unsubscribe(pp, &myloop, evloop_newstate);
            snprintf(json_buf, JSON_BUF_SIZE, UNSUBSCRIBE_MESSAGE, parname->valuestring);
            if (webserver_ws_send(wsdata->client.hd, wsdata->client.socket, json_buf))
                subscribtion_web.erase(wsdata->client.socket);
        }
        else
            ESP_LOGW(TAG, "%s: Unhandled command: %s", __func__, cmd->valuestring);
    }
exit:
    cJSON_Delete(doc);

    return ESP_OK;
}

httpd_uri_t uri_ws = {.uri = "/ws", .method = HTTP_GET, .handler = ws_handler, .user_ctx = NULL, .is_websocket = true, .handle_ws_control_frames = false, .supported_subprotocol = NULL};
httpd_uri_t uri_main = {.uri = "/main.js", .method = HTTP_GET, .handler = get_web, .user_ctx = NULL, .is_websocket = false, .handle_ws_control_frames = false, .supported_subprotocol = NULL};
httpd_uri_t uri_wsclient = {.uri = "/wsclient.js", .method = HTTP_GET, .handler = get_web, .user_ctx = NULL, .is_websocket = false, .handle_ws_control_frames = false, .supported_subprotocol = NULL};
httpd_uri_t uri_vibrationCtrl = {.uri = "/vibrationControl.html", .method = HTTP_GET, .handler = get_web, .user_ctx = NULL, .is_websocket = false, .handle_ws_control_frames = false, .supported_subprotocol = NULL};
httpd_uri_t uri_vibrationCtrlJs = {.uri = "/vibrationControl.js", .method = HTTP_GET, .handler = get_web, .user_ctx = NULL, .is_websocket = false, .handle_ws_control_frames = false, .supported_subprotocol = NULL};

static int sock_err(int sockfd)
{
    int errval;

    switch (errno)
    {
    case EAGAIN:
    case EINTR:
        errval = HTTPD_SOCK_ERR_TIMEOUT;
        break;
    case EINVAL:
    case EBADF:
    case EFAULT:
    case ENOTSOCK:
        errval = HTTPD_SOCK_ERR_INVALID;
        break;
    default:
        errval = HTTPD_SOCK_ERR_FAIL;
    }
    return errval;
}

int httpd_send_override(httpd_handle_t hd, int sockfd, const char *buf, size_t buf_len, int flags)
{
    int ret = -1;
    (void)hd;
    if (buf == NULL)
    {
        return HTTPD_SOCK_ERR_INVALID;
    }

    ret = send(sockfd, buf, buf_len, flags);
    if (ret < 0)
    {
        ESP_LOGW(TAG, "Error in send %d (%d) %s", buf_len, errno, strerror(errno));

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 500 * 1000; // 500 ms

        fd_set set;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);

        ret = select(sockfd + 1, NULL, &set, NULL, &timeout);
        if (ret > 0)
        {
            ret = send(sockfd, buf, buf_len, flags);
            if (ret < 0)
            {
                ESP_LOGW(TAG, "Error in send %d (%d) %s", buf_len, errno, strerror(errno));
                return sock_err(sockfd);
            }
        }
        else if (ret == 0)
        {
            ESP_LOGW(TAG, "Timeout in select %d (%d) %s", buf_len, errno, strerror(errno));
            return sock_err(sockfd);
        }
        else
        {
            ESP_LOGW(TAG, "Error in select %d (%d) %s", buf_len, errno, strerror(errno));
            return sock_err(sockfd);
        }
    }
    return ret;
}

static esp_err_t on_open_socket(httpd_handle_t hd, int sockfd)
{
    httpd_sess_set_send_override(server, sockfd, httpd_send_override);
    // socket_block(sockfd, false);
    open_sockets++;
    return ESP_OK;
}

static void on_close_socket(httpd_handle_t hd, int sockfd)
{
    struct linger so_linger;
    so_linger.l_onoff = true;
    so_linger.l_linger = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
    close(sockfd);
    open_sockets--;
}

void webserver_start()
{
    ESP_EVENT_DECLARE_BASE(EV_BASE);
    myloop.base = EV_BASE;
    myloop.loop_handle = NULL; // default loop

    esp_vfs_spiffs_conf_t spiffs_config = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 30,
        .format_if_mount_failed = true,
    };
    esp_vfs_spiffs_register(&spiffs_config);

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.task_priority = 5;
    config.max_uri_handlers = 6;
    config.stack_size = 512 * 40;
    config.open_fn = on_open_socket;
    config.close_fn = on_close_socket;
    config.recv_wait_timeout = 1;
    config.send_wait_timeout = 1;

    if (httpd_start(&server, &config) == ESP_OK)
    {
        httpd_register_uri_handler(server, &uri_ws);
        httpd_register_uri_handler(server, &uri_main);
        httpd_register_uri_handler(server, &uri_wsclient);
        httpd_register_uri_handler(server, &uri_vibrationCtrl);
        httpd_register_uri_handler(server, &uri_vibrationCtrlJs);
    }

    pp_wsdata = pp_get("WsData");
}
