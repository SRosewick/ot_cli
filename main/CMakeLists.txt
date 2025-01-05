idf_component_register(SRCS "esp_ot_cli.cpp"
                       INCLUDE_DIRS "."
                                    "${IDF_PATH}/components/openthread/openthread/include"
                                    "${IDF_PATH}/components/openthread/openthread/third_party/tcplp/bsdtcp"
                                    "${IDF_PATH}/examples/openthread/ot_cli/components/arduino-esp32/libraries/Grove_Temper_Humidity/"
                                    "${IDF_PATH}/examples/openthread/ot_cli/components/arduino-esp32/libraries/Grove_Air_quality_Sensor/"
                        REQUIRES lwip openthread
                        REQUIRES json
                        PRIV_REQUIRES nvs_flash)

set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/components/libcoap")