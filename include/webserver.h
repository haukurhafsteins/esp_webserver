#include "esp_http_server.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint16_t id;
        uint16_t subid;
        uint8_t context[0];
    } ws_binary_t;

    void webserver_start();
    bool webserver_ws_send(httpd_handle_t hd, int socket, char *data);
    bool webserver_ws_send_binary(httpd_handle_t hd, int socket, void *json, size_t json_len, void* bin, size_t bin_len);

    
#ifdef __cplusplus
}
#endif
