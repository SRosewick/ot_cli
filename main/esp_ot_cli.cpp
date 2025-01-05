#include <stdio.h>
#include <unistd.h>
#include <string>
#include <stdlib.h>

extern "C" {
#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_openthread.h"
#include "esp_openthread_cli.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_ot_config.h"
#include "esp_vfs_eventfd.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/uart_types.h"
#include "nvs_flash.h"

#include "openthread/cli.h"
#include "openthread/instance.h"
#include "openthread/logging.h"
#include "openthread/tasklet.h"
#include "openthread/thread.h" // Required for neighbor info API
#include <openthread/message.h>
#include <openthread/nat64.h>
#include <openthread/udp.h>
#include <ip6.h> 
#include <openthread/coap.h>
#include <openthread/icmp6.h>
#include <openthread/platform/time.h>
#include <openthread/link.h>
#include <cJSON.h>
}

#include <Arduino.h>
#include "Wire.h"
#include "THSensor_base.h"
#include "TH02_dev.h"
#include "Air_Quality_Sensor.h"
//#include "coap3/coap.h"

#if CONFIG_OPENTHREAD_STATE_INDICATOR_ENABLE
#include "ot_led_strip.h"
#endif
#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
#include "esp_ot_cli_extension.h"
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

#define TAG "ot_esp_cli"

#include "sensor_loop_utils.h"

#include "led_strip.h"

#define REMOTE_IP "2003:cf:3704:8a34:24b6:80ca:e497:cc39"    // IPv6 Adresse vom Server

#if defined (GROVER_TEMP_HUM)
otCoapResource hum;
otCoapResource temp;
TH02_dev TH02;
#elif defined (GROVER_AIR_Q)
otCoapResource airQ;
AirQualitySensor air_sensor(GPIO_NUM_1);
#endif

static otUdpSocket udp_socket;
static led_strip_handle_t led_strip;
otCoapResource sLightResource;
otCoapResource core;

#if defined (GROVER_TEMP_HUM)
static void handleTempGET(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
    otError error;
    otMessage *response;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    // Create a CoAP message
    messageSettings.mLinkSecurityEnabled = true; // BR will drop Message if set to false
    messageSettings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

    response = otCoapNewMessage(esp_openthread_get_instance(), &messageSettings);
    if (response == NULL) {
        ESP_LOGI(TAG, "Failed to allocate CoAP message\n");
        return;
    }
    // Prepare the CoAP header
    otCoapMessageInit(response, OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_CONTENT); //OT_COAP_TYPE_CONFIRMABLE
    uint8_t req_token_length = otCoapMessageGetTokenLength(aMessage);
    uint8_t *req_token = otCoapMessageGetToken(aMessage);
    otCoapMessageSetToken(response, req_token, req_token_length);
 
    char ipv6AddrStr[40];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, sizeof(ipv6AddrStr));
    ESP_LOGI(TAG, "Sender IPv6 Address: %s", ipv6AddrStr);
    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = aMessageInfo->mPeerAddr;
    messageInfo.mPeerPort = aMessageInfo->mPeerPort; //5683
    
    // Content Type e.g. Plain Text or JSON
    otCoapMessageAppendContentFormatOption(response, OT_COAP_OPTION_CONTENT_FORMAT_JSON); //OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN
    
    // Marker to indicate that there is a payload and where it begins
    otCoapMessageSetPayloadMarker(response);

    cJSON *tmp_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(tmp_json, "temperature", TH02.ReadTemperature());
    char *string_json = cJSON_Print(tmp_json);
    otMessageAppend(response, (const uint8_t *)string_json, strlen(string_json));

    // Send the CoAP request
    error = otCoapSendResponse(esp_openthread_get_instance(), response, &messageInfo);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send CoAP response: %s\n", otThreadErrorToString(error));
        otMessageFree(response);
    } else {
        ESP_LOGI(TAG, "Sending Succes GET core description");
    }
}

static void handleHumGET(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
    otError error;
    otMessage *response;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    // Create a CoAP message
    messageSettings.mLinkSecurityEnabled = true; // BR will drop Message if set to false
    messageSettings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

    response = otCoapNewMessage(esp_openthread_get_instance(), &messageSettings);
    if (response == NULL) {
        ESP_LOGI(TAG, "Failed to allocate CoAP message\n");
        return;
    }
    // Prepare the CoAP header
    otCoapMessageInit(response, OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_CONTENT); //OT_COAP_TYPE_CONFIRMABLE
    uint8_t req_token_length = otCoapMessageGetTokenLength(aMessage);
    uint8_t *req_token = otCoapMessageGetToken(aMessage);
    otCoapMessageSetToken(response, req_token, req_token_length);
 
    char ipv6AddrStr[40];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, sizeof(ipv6AddrStr));
    ESP_LOGI(TAG, "Sender IPv6 Address: %s", ipv6AddrStr);
    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = aMessageInfo->mPeerAddr;
    messageInfo.mPeerPort = aMessageInfo->mPeerPort; //5683
    
    // Content Type e.g. Plain Text or JSON
    otCoapMessageAppendContentFormatOption(response, OT_COAP_OPTION_CONTENT_FORMAT_JSON); //OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN
    
    // Marker to indicate that there is a payload and where it begins
    otCoapMessageSetPayloadMarker(response);

    cJSON *hum_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(hum_json, "humidity", TH02.ReadHumidity());
    char *string_json = cJSON_Print(hum_json);
    otMessageAppend(response, (const uint8_t *)string_json, strlen(string_json));

    // Send the CoAP request
    error = otCoapSendResponse(esp_openthread_get_instance(), response, &messageInfo);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send CoAP response: %s\n", otThreadErrorToString(error));
        otMessageFree(response);
    } else {
        ESP_LOGI(TAG, "Sending Succes GET core description");
    }
}

#elif defined (GROVER_AIR_Q)
static void handleAirQGET(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
    otError error;
    otMessage *response;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    // Create a CoAP message
    messageSettings.mLinkSecurityEnabled = true; // BR will drop Message if set to false
    messageSettings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

    response = otCoapNewMessage(esp_openthread_get_instance(), &messageSettings);
    if (response == NULL) {
        ESP_LOGI(TAG, "Failed to allocate CoAP message\n");
        return;
    }
    // Prepare the CoAP header
    otCoapMessageInit(response, OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_CONTENT); //OT_COAP_TYPE_CONFIRMABLE
    uint8_t req_token_length = otCoapMessageGetTokenLength(aMessage);
    uint8_t *req_token = otCoapMessageGetToken(aMessage);
    otCoapMessageSetToken(response, req_token, req_token_length);
 
    char ipv6AddrStr[40];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, sizeof(ipv6AddrStr));
    ESP_LOGI(TAG, "Sender IPv6 Address: %s", ipv6AddrStr);
    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = aMessageInfo->mPeerAddr;
    messageInfo.mPeerPort = aMessageInfo->mPeerPort; //5683
    
    // Content Type e.g. Plain Text or JSON
    otCoapMessageAppendContentFormatOption(response, OT_COAP_OPTION_CONTENT_FORMAT_JSON); //OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN
    
    // Marker to indicate that there is a payload and where it begins
    otCoapMessageSetPayloadMarker(response);

    cJSON *airQ_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(airQ, "airquality", air_sensor.getValue(););
    char *string_json = cJSON_Print(airQ_json);
    otMessageAppend(response, (const uint8_t *)string_json, strlen(string_json));

    // Send the CoAP request
    error = otCoapSendResponse(esp_openthread_get_instance(), response, &messageInfo);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send CoAP response: %s\n", otThreadErrorToString(error));
        otMessageFree(response);
    } else {
        ESP_LOGI(TAG, "Sending Succes GET core description");
    }
}
#endif

static void handleLEDPostRequest(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
    otCoapCode coapCode = otCoapMessageGetCode(aMessage);
    otError error;
    if (coapCode == OT_COAP_CODE_POST)
    {
        otMessage *response = otCoapNewMessage(esp_openthread_get_instance(), NULL);
        if (response == NULL)
        {
            otPlatLog(OT_LOG_LEVEL_CRIT, OT_LOG_REGION_COAP, "Failed to allocate response message");
            return;
        }
        uint16_t messageLength = otMessageGetLength(aMessage);
        uint16_t offset = otMessageGetOffset(aMessage);
        uint16_t payloadLength = messageLength - offset;

        // Allocate a buffer to hold the payload
        char *buffer = new char[payloadLength + 1];
        memset(buffer, 0, payloadLength + 1);

        // Read the payload into the buffer
        int bytesRead = otMessageRead(aMessage, offset, buffer, payloadLength);
        ESP_LOGI(TAG, "%s", buffer);
        cJSON *rgb = cJSON_Parse(buffer);

        cJSON *green = cJSON_GetObjectItemCaseSensitive(rgb, "green");
        cJSON *red = cJSON_GetObjectItemCaseSensitive(rgb, "red");
        cJSON *blue = cJSON_GetObjectItemCaseSensitive(rgb, "blue");

        uint8_t r = 0;
        uint8_t g = 0;
        uint8_t b = 0;
        if(cJSON_IsString(red) && red->valuestring != NULL){
            r = std::atoi(red->valuestring);
        }
        if(cJSON_IsString(green) && green->valuestring != NULL){
            g = std::atoi(green->valuestring);
        }
        if(cJSON_IsString(blue) && blue->valuestring != NULL){
            b = std::atoi(blue->valuestring);
        }

        otCoapMessageInit(response, OT_COAP_TYPE_NON_CONFIRMABLE, OT_COAP_CODE_CHANGED);
        otCoapMessageSetToken(response, otCoapMessageGetToken(aMessage), otCoapMessageGetTokenLength(aMessage));
        otCoapMessageSetPayloadMarker(response);

        ESP_ERROR_CHECK(led_strip_clear(led_strip));
        ESP_ERROR_CHECK(led_strip_set_pixel(led_strip, 0, r, g, b));
        ESP_ERROR_CHECK(led_strip_refresh(led_strip));

        // Add the response payload
        const char *responsePayload = "LED set accordingly";
        otMessageAppend(response, responsePayload, strlen(responsePayload));

        // Send the response
        error = otCoapSendResponse(esp_openthread_get_instance(), response, aMessageInfo);
        if (error != OT_ERROR_NONE)
        {
            otMessageFree(response);
            otPlatLog(OT_LOG_LEVEL_CRIT, OT_LOG_REGION_COAP, "Failed to send CoAP response: %s", otThreadErrorToString(error));
        }
    }
    else
    {
        otPlatLog(OT_LOG_LEVEL_WARN, OT_LOG_REGION_COAP, "Unsupported CoAP request code");
    }
}

static void handleCoREFormatDescription(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
    ESP_LOGI(TAG, "GOT CORE REQUEST");
    otError error;
    otMessage *response;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    // Create a CoAP message
    messageSettings.mLinkSecurityEnabled = true; // BR will drop Message if set to false
    messageSettings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

    response = otCoapNewMessage(esp_openthread_get_instance(), &messageSettings);
    if (response == NULL) {
        ESP_LOGI(TAG, "Failed to allocate CoAP message\n");
        return;
    }
    // Prepare the CoAP header
    otCoapMessageInit(response, OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_CONTENT); //OT_COAP_TYPE_CONFIRMABLE
    uint8_t req_token_length = otCoapMessageGetTokenLength(aMessage);
    uint8_t *req_token = otCoapMessageGetToken(aMessage);
    otCoapMessageSetToken(response, req_token, req_token_length);
 
    char ipv6AddrStr[40];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, sizeof(ipv6AddrStr));
    ESP_LOGI(TAG, "Sender IPv6 Address: %s", ipv6AddrStr);
    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = aMessageInfo->mPeerAddr;
    messageInfo.mPeerPort = aMessageInfo->mPeerPort; //5683
    
    // Content Type e.g. Plain Text or JSON
    otCoapMessageAppendContentFormatOption(response, OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN); //OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN
    
    // Marker to indicate that there is a payload and where it begins
    otCoapMessageSetPayloadMarker(response);

    std::string core;
    #if defined (GROVER_TEMP_HUM)
    core += "</temperature>;rt=\"TemperatureC\";if=\"sensor\",";
    core += "</humidity>;rt=\"HumidityRH\";if=\"sensor\",";
    #elif defined (GROVER_AIR_Q)
    core+= "</sensors/airquality>;rt=\"AirQualitymV\";if=\"sensor\",";
    #endif
    core += "</led>;rt=\"WS2812b\";if=\"actuator\"";
    otMessageAppend(response, (const uint8_t *)core.data(), core.size());

    // Send the CoAP request
    error = otCoapSendResponse(esp_openthread_get_instance(), response, &messageInfo);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send CoAP response: %s\n", otThreadErrorToString(error));
        otMessageFree(response);
    } else {
        ESP_LOGI(TAG, "Sending Succes GET core description");
    }
}

void initCoapServer(otInstance *aInstance)
{
    core.mUriPath = ".well-known/core";
    core.mHandler = handleCoREFormatDescription;
    core.mContext = NULL;
    core.mNext = NULL;
    otCoapAddResource(aInstance, &core);

    #if defined (GROVER_TEMP_HUM)
    temp.mUriPath = "temperature";
    temp.mHandler = handleTempGET;
    temp.mContext = NULL;
    temp.mNext = NULL;
    
    hum.mUriPath = "humidity";
    hum.mHandler = handleHumGET;
    hum.mContext = NULL;
    hum.mNext = NULL;
    
    otCoapAddResource(aInstance, &temp);
    otCoapAddResource(aInstance, &hum);
    #elif defined (GROVER_AIR_Q)
    air.QmUriPath = "airquality";
    air.QmHandler = handleAirQGET;
    air.QmContext = NULL;
    air.QmNext = NULL;
    otCoapAddResource(aInstance, &qirQ);
    #endif
    // Initialize the CoAP WS2812b LED resource
    sLightResource.mUriPath = "led";
    sLightResource.mHandler = handleLEDPostRequest;
    sLightResource.mContext = NULL;
    sLightResource.mNext = NULL;

    // Register the resource with the CoAP server
    otCoapAddResource(aInstance, &sLightResource);
}

void coap_response_handler(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo, otError aResult)
{
    if (aResult == OT_ERROR_NONE) {
        ESP_LOGI(TAG, "CoAP response received\n");
    } else {
        ESP_LOGI(TAG, "Failed to receive CoAP response: %d\n", aResult);
    }
    if (aMessage == NULL) {
        ESP_LOGE(TAG, "Message is NULL");
        return;
    }

    // Get the message payload length
    uint16_t messageLength = otMessageGetLength(aMessage);
    uint16_t offset = otMessageGetOffset(aMessage);
    uint16_t payloadLength = messageLength - offset;

    // Allocate a buffer to hold the payload
    char *buffer = new char[payloadLength + 1]; // +1 for null-termination
    memset(buffer, 0, payloadLength + 1);

    // Read the payload into the buffer
    int bytesRead = otMessageRead(aMessage, offset, buffer, payloadLength);
    if (bytesRead != payloadLength) {
        ESP_LOGE(TAG, "Failed to read full payload: expected %d, got %d", payloadLength, bytesRead);
        delete[] buffer;
        return "";
    }

    ESP_LOGI(TAG, "Response from Server: \"%s\"", buffer);
    // Clean up the buffer
    delete[] buffer;
}


static esp_netif_t *init_openthread_netif(const esp_openthread_platform_config_t *config)
{
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
    esp_netif_t *netif = esp_netif_new(&cfg);
    assert(netif != NULL);
    ESP_ERROR_CHECK(esp_netif_attach(netif, esp_openthread_netif_glue_init(config)));

    return netif;
}

void udp_receive_callback(void *context, otMessage *message, const otMessageInfo *messageInfo)
{
    char buf[128];
    int length = otMessageRead(message, otMessageGetOffset(message), buf, sizeof(buf) - 1);
    buf[length] = '\0';

    ESP_LOGI(TAG, "Received message: %s", buf);
}

void udp_server_init(otInstance *instance)
{
    otUdpOpen(instance, &udp_socket, udp_receive_callback, NULL);

    otSockAddr sockaddr;
    otIp6Address destAddr;
    otIp6AddressFromString(REMOTE_IP, &destAddr);
    
    sockaddr.mPort = REMOTE_PORT;
    sockaddr.mAddress = destAddr;

    if(otUdpConnect(instance, &udp_socket, &sockaddr) != OT_ERROR_NONE){
        ESP_LOGI(TAG, "Failed to open udp socket");
    }
}

void udp_client_send_message(otInstance *instance, const char *message, const otIp6Address *destAddr)
{
    otError error;
    otMessageInfo messageInfo;
    otMessage *otMessage;

    otMessage = otUdpNewMessage(instance, NULL);
    otMessageAppend(otMessage, message, strlen(message));

    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = *destAddr;
    messageInfo.mPeerPort = REMOTE_PORT;

    error = otUdpSend(instance, &udp_socket, otMessage, &messageInfo);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send UDP message: %s", otThreadErrorToString(error));
        otMessageFree(otMessage);
    } else {
        ESP_LOGI(TAG, "Message sent: %s", message);
    }
}

void send_coap_request_sensor_data(otInstance *instance, const char *message, const otIp6Address *destAddr)
{
    if(instance == NULL){
        ESP_LOGI(TAG, "Instance is Null");
        return;
    }
    otError error;
    otMessage *request;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    // Create a CoAP message
    messageSettings.mLinkSecurityEnabled = true; // BR will drop Message if set to false
    messageSettings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

    request = otCoapNewMessage(instance, &messageSettings);
    if (request == NULL) {
        ESP_LOGI(TAG, "Failed to allocate CoAP message\n");
        return;
    }
    // Prepare the CoAP header
    otCoapMessageInit(request, OT_COAP_TYPE_NON_CONFIRMABLE, OT_COAP_CODE_POST); //OT_COAP_TYPE_CONFIRMABLE
    otCoapMessageGenerateToken(request, OT_COAP_DEFAULT_TOKEN_LENGTH);
    otCoapMessageAppendUriPathOptions(request, "hello_test");


    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = *destAddr;
    messageInfo.mPeerPort = OT_DEFAULT_COAP_PORT; //5683
    
    // Content Type e.g. Plain Text or JSON
    otCoapMessageAppendContentFormatOption(request, OT_COAP_OPTION_CONTENT_FORMAT_JSON); //OT_COAP_OPTION_CONTENT_FORMAT_TEXT_PLAIN
    
    // Marker to indicate that there is a payload and where it begins
    otCoapMessageSetPayloadMarker(request);

    otMessageAppend(request, (const uint8_t *)message, strlen(message));

    // Send the CoAP request
    error = otCoapSendRequest(instance, request, &messageInfo, coap_response_handler, NULL);
    if (error != OT_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to send CoAP request: %s\n", otThreadErrorToString(error));
        otMessageFree(request);
    } else {
        ESP_LOGI(TAG, "Sending Succes");
    }
}


static void sensor_data_loop(void *param) {
    vTaskDelay(pdMS_TO_TICKS(2*SLEEP_MS));
    
    led_strip_config_t strip_config = {
        .strip_gpio_num = GPIO_NUM_8,  // The GPIO that connected to the LED strip's data line
        .max_leds = 1,                 // The number of LEDs in the strip,
        .led_model = LED_MODEL_WS2812, // LED strip model, it determines the bit timing
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB, // The color component format is G-R-B
        .flags = {
            .invert_out = false, // don't invert the output signal
        }
    };

    /// RMT backend specific configuration
    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,    // different clock source can lead to different power consumption
        .resolution_hz = 10 * 1000 * 1000, // RMT counter clock frequency: 10MHz
        .mem_block_symbols = 64,           // the memory size of each RMT channel, in words (4 bytes)
        .flags = {
            .with_dma = false, // DMA feature is available on chips like ESP32-S3/P4
        }
    };
    /// Create the LED strip object
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));

    otInstance *instance = esp_openthread_get_instance();

    otError coapError = otCoapStart(instance, OT_DEFAULT_COAP_PORT);

    ESP_LOGI(TAG, "%s",otThreadErrorToString(coapError));
    if (coapError != OT_ERROR_NONE) {
        ESP_LOGI(TAG, "Failed to start Coap");
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(SLEEP_MS));
    initCoapServer(instance);

    #if defined (GROVER_TEMP_HUM)
    Wire.begin(22, 12);
    TH02.begin();
    vTaskDelay(pdMS_TO_TICKS(SLEEP_MS));
    float temper;
    float hum;
    #elif defined (GROVER_AIR_Q)
    int air_sensor_val;
    vTaskDelay(pdMS_TO_TICKS(20 * SLEEP_MS));   // Sensor Warmup
    #endif



    // Task Main-Loop
    while (true)
    {
        #if defined (GROVER_TEMP_HUM)        
        temper = TH02.ReadTemperature();
        hum = TH02.ReadHumidity();
        #elif defined (GROVER_AIR_Q)
        int quality = air_sensor.slope();
        air_sensor_val = air_sensor.getValue();        
        #endif        
        otNeighborInfoIterator iterator = OT_NEIGHBOR_INFO_ITERATOR_INIT;
        otNeighborInfo neighborInfo;

        // Address from Server
        otIp6Address destAddr;
        otIp6AddressFromString(REMOTE_IP, &destAddr);

        // Build JSON Data-Structure
        cJSON *root = cJSON_CreateObject();
        cJSON *rssi = cJSON_CreateArray();
                
        // My Mac-Address
        if (instance == NULL)
        {
            ESP_LOGE(TAG, "OpenThread instance is not initialized.");
            return;    
        }
        const otExtAddress *extAddress = otLinkGetExtendedAddress(instance);
        if (extAddress == NULL)
        {
            ESP_LOGE(TAG, "Failed to retrieve MAC address.");
            return;
        }
        char own_mac[24];
        sprintf(own_mac, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", extAddress->m8[0],
                                                                    extAddress->m8[1],
                                                                    extAddress->m8[2],
                                                                    extAddress->m8[3],
                                                                    extAddress->m8[4],
                                                                    extAddress->m8[5],
                                                                    extAddress->m8[6],
                                                                    extAddress->m8[7]);
        cJSON_AddStringToObject(root, "mac_addr", own_mac);

        //My Routing Locator
        uint16_t my_rloc16 = otThreadGetRloc16(instance);
        char rloc_string[7];
        sprintf(rloc_string, "0x%04X", my_rloc16);
        cJSON_AddStringToObject(root, "RLOC16", rloc_string);

        // Timestamp
        cJSON_AddNumberToObject(root, "timestamp_ms", otPlatTimeGet());

        // TX Power
        int8_t aPower = 0;
        if(otPlatRadioGetTransmitPower(instance, &aPower) != OT_ERROR_NONE){
            ESP_LOGE(TAG, "Can't get TX Power.");
        }
        cJSON_AddNumberToObject(root, "tx_pwr", aPower);

        // Iterate over each neighbor for RSSI values
        int i = 1;
        while (otThreadGetNextNeighborInfo(instance, &iterator, &neighborInfo) == OT_ERROR_NONE)
        {
            cJSON *neighbor = cJSON_CreateObject();
            char neighbor_mac[24];
            sprintf(neighbor_mac, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", neighborInfo.mExtAddress.m8[0],
                                                                             neighborInfo.mExtAddress.m8[1],
                                                                             neighborInfo.mExtAddress.m8[2],
                                                                             neighborInfo.mExtAddress.m8[3],
                                                                             neighborInfo.mExtAddress.m8[4],
                                                                             neighborInfo.mExtAddress.m8[5],
                                                                             neighborInfo.mExtAddress.m8[6],
                                                                             neighborInfo.mExtAddress.m8[7]);

            cJSON_AddStringToObject(neighbor, "MAC", neighbor_mac);
            cJSON_AddNumberToObject(neighbor, "RSSI_AVG", neighborInfo.mAverageRssi);
            char neighbor_name[22];
            sprintf(neighbor_name, "neighbor%d", i++);
            cJSON_AddItemToArray(rssi, neighbor);
        }
        // Get errors on Link Layer
        const otMacCounters *mac_counter = otLinkGetCounters(instance);
        cJSON_AddNumberToObject(root, "MAC_RxErrFcs", mac_counter->mRxErrFcs);
        cJSON_AddNumberToObject(root, "MAC_TxErrAbort", mac_counter->mTxErrAbort);

        //Get Errors and IP Layer
        const otIpCounters *ip_counter  = otThreadGetIp6Counters(instance);
        cJSON_AddNumberToObject(root, "IP_RxFailures", ip_counter->mRxFailure);
        cJSON_AddNumberToObject(root, "IP_TxFailures", ip_counter->mTxFailure);

        #if defined (GROVER_TEMP_HUM)
        cJSON_AddNumberToObject(root, "temperature", temper);
        cJSON_AddNumberToObject(root, "humidity", hum);
                
        #elif defined(GROVER_AIR_Q)
        cJSON_AddNumberToObject(root, "GROVER_AIR_Quality", air_sensor_val);
        #endif
        
        cJSON_AddItemToObject(root, "neighbor_rssi", rssi);
        //udp_client_send_message(instance, cJSON_Print(root), &destAddr);
        //ESP_LOGI(TAG, "%s", cJSON_Print(root));
        send_coap_request_sensor_data(instance, cJSON_Print(root), &destAddr);
        cJSON_Delete(root);
        vTaskDelay(pdMS_TO_TICKS(5*SLEEP_MS));
        
    }   //Task Main-Loop
}

static void ot_task_worker(void *aContext)
{
    esp_openthread_platform_config_t config = {
        .radio_config = ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_OPENTHREAD_DEFAULT_HOST_CONFIG(),
        .port_config = ESP_OPENTHREAD_DEFAULT_PORT_CONFIG(),
    };

    // Initialize the OpenThread stack
    ESP_ERROR_CHECK(esp_openthread_init(&config));

#if CONFIG_OPENTHREAD_STATE_INDICATOR_ENABLE
    ESP_ERROR_CHECK(esp_openthread_state_indicator_init(esp_openthread_get_instance()));
#endif

#if CONFIG_OPENTHREAD_LOG_LEVEL_DYNAMIC
    // The OpenThread log level directly matches ESP log level
    (void)otLoggingSetLevel(CONFIG_LOG_DEFAULT_LEVEL);
#endif
    // Initialize the OpenThread cli
#if CONFIG_OPENTHREAD_CLI
    esp_openthread_cli_init();
#endif

    esp_netif_t *openthread_netif;
    // Initialize the esp_netif bindings
    openthread_netif = init_openthread_netif(&config);
    esp_netif_set_default_netif(openthread_netif);

#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    esp_cli_custom_command_init();
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

    // Run the main loop
#if CONFIG_OPENTHREAD_CLI
    esp_openthread_cli_create_task();
#endif
#if CONFIG_OPENTHREAD_AUTO_START
    otOperationalDatasetTlvs dataset;
    otError error = otDatasetGetActiveTlvs(esp_openthread_get_instance(), &dataset);
    ESP_ERROR_CHECK(esp_openthread_auto_start((error == OT_ERROR_NONE) ? &dataset : NULL));
#endif
    esp_openthread_launch_mainloop();

    // Clean up
    esp_openthread_netif_glue_deinit();
    esp_netif_destroy(openthread_netif);

    esp_vfs_eventfd_unregister();
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    // Used eventfds:
    // * netif
    // * ot task queue
    // * radio driver
    esp_vfs_eventfd_config_t eventfd_config = {
        .max_fds = 3,
    };

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));
    xTaskCreate(ot_task_worker, "ot_cli_main", 10240, xTaskGetCurrentTaskHandle(), 5, NULL);
    xTaskCreate(sensor_data_loop, "neighbor_rssi_task", 4096, NULL, 5, NULL);

}