idf_component_register(SRCS "webserver.cpp"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES "esp_http_server" "esp_public_parameter" "esp_websocket_client" "esp_ethernet" "mdns" "spiffs" "cjson")
                    
