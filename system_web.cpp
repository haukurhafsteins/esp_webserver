#include <stdlib.h>
#include "esp_http_server.h"
#include "ethernet.h"

static const char *doc_start_to_body = "<!DOCTYPE html> \
<html><head>\
<title>PARAMS</title>\
<style>\
body {\
  font-family: Arial, Helvetica, sans-serif;\
}\
pre {\
    font-size: 1.1em;\
}\
table {\
  border-collapse: collapse;\
}\
th, td {\
  font-size: 0.9em;\
  text-align: left;\
  padding: 6px;\
  border: 1px solid #ddd;\
}\
tr:nth-child(even) {background-color: #f2f2f2;}\
</style>\
</head>\
<body>";
static const char *button = "<button onclick=\"window.location.href='http://%s/metrics?%s'\">%s</button>";
static const char *hdr_nvs_var_begin = "<h3>MASI - Non Volatile Storage Variables</h3><table>";
static const char *hdr_tasks_begin = "<h3>MASI - Tasks</h3><table>";
static const char *hdr_memory_begin = "<h3>MASI - Memory</h3><table>";
static const char *hdr_table_end = "</table>";
static const char *doc_body_to_end = "<script type=\"text/javascript\">\
    const el = document.getElementsByClassName(\"json\");\
    for(var i = 0; i < el.length; i++)\
        el[i].innerHTML = JSON.stringify(JSON.parse(el[i].innerHTML), undefined, 4);\
</script></body></html>";

static void print_buttons(httpd_req_t *req, char *buf, size_t bufsize)
{
    const char *p = ethernet_get_hostname();

    snprintf(buf, bufsize, button, p, "nvs=true", "Configuration");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, button, p, "public=true", "Public Parameters");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, button, p, "web_clients=true", "Web Clients");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, button, p, "tasks=1", "Tasks");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, button, p, "memory=1", "Memory");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, button, p, "discovery=1", "Discovery");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
}

static void print_nvs_configuration(httpd_req_t *req, char *buf, size_t bufsize)
{
    const char *nvs_header = "<tr><th>Namespace</th><th>Name</th><th>Type</th><th>Value</th></tr>";
    httpd_resp_send_chunk(req, hdr_nvs_var_begin, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, nvs_header, HTTPD_RESP_USE_STRLEN);
    nvs_handle_t h;
    if (nvs_open_storage(NVS_READONLY, &h))
    {
        nvs_iterator_t it = nvs_entry_find("nvs", NULL, NVS_TYPE_ANY);
        while (it != NULL)
        {
            nvs_entry_info_t info;
            nvs_entry_info(it, &info);
            it = nvs_entry_next(it);

            if (info.type == NVS_TYPE_STR)
            {
                char s[bufsize - 100];
                size_t len = bufsize;
                nvs_read_str(h, info.key, s, &len);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>String</td><td><pre class=\"json\">%s</pre></td></tr>", info.namespace_name, info.key, s);
            }
            else if (info.type == NVS_TYPE_U8)
            {
                uint8_t i = 0;
                nvs_read_u8(h, info.key, &i);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>int8_t</td><td>%d</td></tr>", info.namespace_name, info.key, i);
            }
            else if (info.type == NVS_TYPE_U16)
            {
                uint16_t i = 0;
                nvs_read_u16(h, info.key, &i);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>int32_t</td><td>%d</td></tr>", info.namespace_name, info.key, i);
            }
            else if (info.type == NVS_TYPE_U32)
            {
                uint32_t i = 0;
                nvs_read_u32(h, info.key, &i);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>int32_t</td><td>%d</td></tr>", info.namespace_name, info.key, i);
            }
            else if (info.type == NVS_TYPE_BLOB)
            {
                float f = 0;
                nvs_read_float(h, info.key, &f);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>Float</td><td>%f</td></tr>", info.namespace_name, info.key, f);
            }
            else if (info.type == NVS_TYPE_I32)
            {
                int32_t i = 0;
                nvs_read_i32(h, info.key, &i);
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>int32_t</td><td>%d</td></tr>", info.namespace_name, info.key, i);
            }
            else
            {
                snprintf(buf, bufsize, "<tr><td>%s</td><td>%s</td><td>int32_t</td><td>Unknown</td></tr>", info.namespace_name, info.key);
            }
            httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
        };
        nvs_close(h);
    }

    httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);
}

static void print_tasks(httpd_req_t *req, char *buf, size_t bufsize, const char *param)

{
    TaskStatus_t *pxTaskStatusArray;
    volatile UBaseType_t uxArraySize, x;
    uint32_t ulTotalRunTime, ulStatsAsPercentage;

    *buf = 0x00;

    uxArraySize = uxTaskGetNumberOfTasks();
    pxTaskStatusArray = (TaskStatus_t *)pvPortMalloc(uxArraySize * sizeof(TaskStatus_t));

    if (pxTaskStatusArray != NULL)
    {
        uxArraySize = uxTaskGetSystemState(pxTaskStatusArray,
                                           uxArraySize,
                                           &ulTotalRunTime);

        /* For percentage calculations. */
        ulTotalRunTime /= 100UL;

        if (ulTotalRunTime > 0)
        {
            const char *task_state[6] = {"Running", "Ready", "Blocked", "Suspended", "Deleted", "Invalid"};
            const char *tasks_header = "<tr><th>Name</th><th>Nr.</th><th>State</th><th>Current Priority</th><th>Base Priority</th><th>Run Time (%%)</th><th>Stack High</th></tr>";
            httpd_resp_send_chunk(req, hdr_tasks_begin, HTTPD_RESP_USE_STRLEN);
            sprintf(buf, "<p>Free Heap Size: %d</p>", xPortGetFreeHeapSize());
            httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
            httpd_resp_send_chunk(req, tasks_header, HTTPD_RESP_USE_STRLEN);
            for (x = 0; x < uxArraySize; x++)
            {
                /* What percentage of the total run time has the task used?
                This will always be rounded down to the nearest integer.
                ulTotalRunTimeDiv100 has already been divided by 100. */
                ulStatsAsPercentage = pxTaskStatusArray[x].ulRunTimeCounter / ulTotalRunTime;

                // "<tr><th>Name</th><th>Nr.</th><th>State</th><th>Current Priority</th><th>Base Priority</th><th>Run Time (%%)</th><th>Stack High</th></tr>"
                sprintf(buf, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>",
                        pxTaskStatusArray[x].pcTaskName,
                        pxTaskStatusArray[x].xTaskNumber,
                        task_state[pxTaskStatusArray[x].eCurrentState],
                        pxTaskStatusArray[x].uxCurrentPriority,
                        pxTaskStatusArray[x].uxBasePriority,
                        ulStatsAsPercentage,
                        pxTaskStatusArray[x].usStackHighWaterMark);
                httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
                buf += strlen((char *)buf);
            }
            httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);
        }

        vPortFree(pxTaskStatusArray);
    }
}

static void print_memory(httpd_req_t *req, char *buf, size_t bufsize)
{
    const char *mem_name[11] = {"Executable", "32 Bit", "8 Bit", "DMA", "SPIRAM", "Internal", "Default", "IRAM 8 Bit", "Retention", "RTCRAM", "Invalid"};
    int32_t caps[11] = {MALLOC_CAP_EXEC, MALLOC_CAP_32BIT, MALLOC_CAP_8BIT, MALLOC_CAP_DMA, MALLOC_CAP_SPIRAM, MALLOC_CAP_INTERNAL, MALLOC_CAP_DEFAULT, MALLOC_CAP_IRAM_8BIT, MALLOC_CAP_RETENTION, MALLOC_CAP_RTCRAM, MALLOC_CAP_INVALID};
    httpd_resp_send_chunk(req, hdr_memory_begin, HTTPD_RESP_USE_STRLEN);
    snprintf(buf, bufsize, "<tr> <th>Memory Name</th> <th>Total Free Bytes</th> <th>Total Allocated Bytes</th> <th>Largest Free Block</th> <th>Minimum Free Bytes</th><th>Allocated Blocks</th> <th>Free Blocks</th> <th>Total Blocks</th> </tr>");
    httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    for (int i = 0; i < 11; i++)
    {
        multi_heap_info_t info;
        heap_caps_get_info(&info, caps[i]);
        snprintf(buf, bufsize, "<tr><th>%s</th><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>",
                 mem_name[i], info.total_free_bytes, info.total_allocated_bytes, info.largest_free_block, info.minimum_free_bytes, info.allocated_blocks, info.free_blocks, info.total_blocks);
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, hdr_table_end, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, "<p><b>Total Free Bytes:</b> Total free bytes in the heap.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Total Allocated Bytes:</b> Total bytes allocated to data in the heap.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Largest Free Block:</b> Size of largest free block in the heap. This is the largest malloc-able size.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Minimum Free Bytes:</b> Lifetime minimum free heap size.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Allocated Blocks:</b> Number of (variable size) blocks allocated in the heap.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Free Blocks:</b> Number of (variable size) free blocks in the heap.", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<p><b>Total Blocks:</b> Total number of (variable size) blocks in the heap.", HTTPD_RESP_USE_STRLEN);
}

esp_err_t get_handler(httpd_req_t *req)
{
    const int bufsize = 4096;
    char *buf = (char *)calloc(bufsize, sizeof(char));

    httpd_resp_send_chunk(req, doc_start_to_body, HTTPD_RESP_USE_STRLEN);
    print_buttons(req, buf, bufsize);

    const int buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1)
    {
        char *buf1 = (char *)malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf1, buf_len) == ESP_OK)
        {
            char param[32];
//            if (httpd_query_key_value(buf1, "twiddle_factors", param, sizeof(param)) == ESP_OK)
//                print_twiddle_factors(req, buf, bufsize, atoi(param));
            if (httpd_query_key_value(buf1, "nvs", param, sizeof(param)) == ESP_OK)
                print_nvs_configuration(req, buf, bufsize);
//            if (httpd_query_key_value(buf1, "public", param, sizeof(param)) == ESP_OK)
//                print_public_parameters(req, buf, bufsize);
//            if (httpd_query_key_value(buf1, "web_clients", param, sizeof(param)) == ESP_OK)
//                print_web_clients(req, buf, bufsize);
//            if (httpd_query_key_value(buf1, "hanning", param, sizeof(param)) == ESP_OK)
//                print_hanning(req, buf, bufsize, atoi(param));
            if (httpd_query_key_value(buf1, "tasks", param, sizeof(param)) == ESP_OK)
                print_tasks(req, buf, bufsize, param);
            if (httpd_query_key_value(buf1, "memory", param, sizeof(param)) == ESP_OK)
                print_memory(req, buf, bufsize);
//            if (httpd_query_key_value(buf1, "discovery", param, sizeof(param)) == ESP_OK)
//                print_discovery(req, buf, bufsize);
        }
        free(buf1);
    }

    httpd_resp_send_chunk(req, doc_body_to_end, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, buf, 0);

    free(buf);

    return ESP_OK;
}