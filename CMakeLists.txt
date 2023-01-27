idf_component_register(SRCS "webserver.cpp"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES "esp_http_server" "esp_public_parameter" "timeman" "esp_websocket_client" "nvs_flash" "nvsstorage" "esp_ethernet" "discovery" "mdns" "spiffs" "cjson" "esp_system_web")
                    
