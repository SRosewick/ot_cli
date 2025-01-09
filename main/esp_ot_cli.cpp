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
#include <openthread/nat64.h> 
}

#include <Arduino.h>
#include "Wire.h"
#include "THSensor_base.h"
#include "TH02_dev.h"
#include "Air_Quality_Sensor.h"
#include <thread>
//#include "coap3/coap.h"

#if CONFIG_OPENTHREAD_STATE_INDICATOR_ENABLE    // RGB according to role in Thread
#include "ot_led_strip.h"
#endif
#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
#include "esp_ot_cli_extension.h"
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

#define TAG "ot_esp_cli"


// #include "sensor_loop_utils.h"

#include "led_strip.h"

#define SLEEP_MS 1000  // Task Loop interval in milliseconds

#define REMOTE_PORT 18090

// #define GROVER_TEMP_HUM
//#define GROVER_AIR_Q
//#define SENSIRION_SCD30
//#define ASAIR_AM2302
//#define LED_STRIP

#define BULTIN_LED GPIO_NUM_8

#define LED_STRIP_GPIO GPIO_NUM_22
#define LED_STRIP_LENGTH 50

#define REMOTE_IP "fd59:30c5:5d96:0:94cd:7bb8:c0ad:3ea5"    // IPv6 Adresse vom Server
#define REMOTE_IPV4 "10.0.32.22"

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

#if defined (LED_STRIP)
otCoapResource ledResource;
#endif

otCoapResource core;

void AddUnicastAddress(otInstance *aInstance)
{
    otError error;
    otNetifAddress address;

    memset(&address, 0, sizeof(address));

    otIp4Address ip4Addr;
    otIp6Address ip6Addr;
    otIp4AddressFromString("10.0.32.204", &ip4Addr);

    otNat64SynthesizeIp6Address(aInstance, &ip4Addr, &ip6Addr);

    address.mAddress = ip6Addr;

    address.mPrefixLength = 64;

    address.mAddressOrigin = OT_ADDRESS_ORIGIN_MANUAL;

    address.mPreferred = false;
    address.mValid = true;

    // Add the unicast address to the Thread interface
    error = otIp6AddUnicastAddress(aInstance, &address);

    if (error == OT_ERROR_NONE)
    {
        ESP_LOGI(TAG, "Successfully added the unicast IPv6 address.\n");
        char test[OT_IP6_ADDRESS_STRING_SIZE];
        otIp6AddressToString(&ip6Addr, test, OT_IP6_ADDRESS_STRING_SIZE);
        ESP_LOGI(TAG, "%s", test);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to add the unicast IPv6 address: %d\n", error);
    }
}

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
 
    char ipv6AddrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, OT_IP6_ADDRESS_STRING_SIZE);
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
    cJSON_Delete(tmp_json);

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
 
    char ipv6AddrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, OT_IP6_ADDRESS_STRING_SIZE);
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
    cJSON_Delete(hum_json);

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
 
    char ipv6AddrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, OT_IP6_ADDRESS_STRING_SIZE);
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
    cJSON_AddNumberToObject(airQ_json, "airquality", air_sensor.getValue());
    char *string_json = cJSON_Print(airQ_json);
    otMessageAppend(response, (const uint8_t *)string_json, strlen(string_json));
    cJSON_Delete(airQ_json);

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

void run_LEDs(led_strip_handle_t *led_strip, int g, int r, int b){
        ESP_ERROR_CHECK(led_strip_clear(*led_strip));

        for(int i = 0; i < LED_STRIP_LENGTH; i++){
            ESP_ERROR_CHECK(led_strip_set_pixel(*led_strip, i, g, r, b));
            ESP_ERROR_CHECK(led_strip_refresh(*led_strip));
            vTaskDelay(pdMS_TO_TICKS(0.05 * SLEEP_MS));
            ESP_ERROR_CHECK(led_strip_set_pixel(*led_strip, i, 0, 0, 0));
            ESP_ERROR_CHECK(led_strip_refresh(*led_strip));
        }
}

#if defined (LED_STRIP)
static void handleLEDStripPostRequest(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo){
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

        // Add the response payload
        std::string responsePayload = "LED set to ";
        responsePayload += ("red: " + std::to_string(r) + ", green: " + std::to_string(g) + ", blue: " + std::to_string(b));
        otMessageAppend(response, (const void *)responsePayload.data(), responsePayload.size());

        // Send the response
        error = otCoapSendResponse(esp_openthread_get_instance(), response, aMessageInfo);
        if (error != OT_ERROR_NONE)
        {
            otMessageFree(response);
            otPlatLog(OT_LOG_LEVEL_CRIT, OT_LOG_REGION_COAP, "Failed to send CoAP response: %s", otThreadErrorToString(error));
        }
        std::thread led_runner(run_LEDs, &led_strip, g, r, b);
        led_runner.detach();
    }
    else
    {
        otPlatLog(OT_LOG_LEVEL_WARN, OT_LOG_REGION_COAP, "Unsupported CoAP request code");
    }
}
#endif

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
 
    char ipv6AddrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&aMessageInfo->mPeerAddr, ipv6AddrStr, OT_IP6_ADDRESS_STRING_SIZE);
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
    #if defined (LED_STRIP)
    core += "</led>;rt=\"WS2812b Strip\";if=\"actuator\"",;
    #endif
    core += "</builtin_led>;rt=\"Builtin WS2812b Strip\";if=\"actuator\"";
    
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
    airQ.mUriPath = "airquality";
    airQ.mHandler = handleAirQGET;
    airQ.mContext = NULL;
    airQ.mNext = NULL;
    otCoapAddResource(aInstance, &airQ);
    #endif
    #if defined (LED_STRIP)
    // Initialize the CoAP WS2812b LED resource
    ledResource.mUriPath = "led";
    ledResource.mHandler = handleLEDStripPostRequest;
    ledResource.mContext = NULL;
    ledResource.mNext = NULL;
    // Register the resource with the CoAP server
    otCoapAddResource(aInstance, &ledResource);
    #endif

    // location.mUriPath = "set_location";
    // location.mHandler = handleLocationPOST;
    // location.mContext = NULL;
    // location.mNext = NULL;

    // otCoapAddResource(aInstance, location);

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
    otCoapMessageAppendUriPathOptions(request, "sensor"); // besser otCoapMessageAppendProxyUriOption ??


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

void send_coap_request_sensor_data_nat64(otInstance *instance, const char *message)
{
    if(instance == NULL){
        ESP_LOGI(TAG, "Instance is Null");
        return;
    }
    otError error;
    otMessage *request;
    otMessageInfo messageInfo;
    otMessageSettings messageSettings;

    otIp4Address ipv4_addr;
    otIp6Address ipv6_addr;
    otIp4AddressFromString(REMOTE_IPV4, &ipv4_addr);

    otNat64SynthesizeIp6Address(esp_openthread_get_instance(), &ipv4_addr, &ipv6_addr);
    

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
    otCoapMessageAppendUriPathOptions(request, "sensor"); // besser otCoapMessageAppendProxyUriOption ??


    // Set the destination address
    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.mPeerAddr = ipv6_addr;
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
    
    // init the lead strip
    led_strip_config_t strip_config = {
        .strip_gpio_num = LED_STRIP_GPIO,  // The GPIO that connected to the LED strip's data line
        .max_leds = 50,                 // The number of LEDs in the strip,
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

    //AddUnicastAddress(instance);

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

        // ot IPv6 addresses
        cJSON *netifIPv6Addresses = cJSON_CreateArray();
        otNetifAddress *netifAddress = otIp6GetUnicastAddresses(instance);
        while(netifAddress->mNext != NULL){
            char string_addr[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(&netifAddress->mAddress, string_addr, OT_IP6_ADDRESS_STRING_SIZE);
            cJSON *str = cJSON_CreateString(string_addr);
            cJSON_AddItemToArray(netifIPv6Addresses, str);
            netifAddress = netifAddress->mNext;
        }
        cJSON_AddItemToObject(root, "ot_netif_ipv6_addr", netifIPv6Addresses);

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
        cJSON_AddNumberToObject(root, "air_quality", air_sensor_val);
        #endif
        
        cJSON_AddItemToObject(root, "neighbor_rssi", rssi);
        //udp_client_send_message(instance, cJSON_Print(root), &destAddr);
        //ESP_LOGI(TAG, "%s", cJSON_Print(root));
        //send_coap_request_sensor_data(instance, cJSON_Print(root), &destAddr);
        send_coap_request_sensor_data_nat64(instance, cJSON_Print(root));
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