import asyncio
import aiocoap
import logging

# Enable debug logging
# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.WARNING)

async def get_coap_core():
    uri = "coap://[FDD5:419B:99E7:1:5656:D596:4AC8:7CCB]:5683/temperature"
    context = await aiocoap.Context.create_client_context()

    try:
        # Create a GET request message
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        print(f"Sending GET request to: {uri}")

        # Send the request and wait for any response
        response = await asyncio.wait_for(context.request(request).response, timeout=10)

        # Log the response
        print("Response Code:", response.code)
        print("Payload:", response.payload.decode('utf-8'))

    except asyncio.TimeoutError:
        print("Request timed out. The server did not respond in time.")
    except Exception as e:
        print("Error during CoAP request:", e)
    finally:
        # Shutdown the context
        await context.shutdown()

if __name__ == "__main__":
    asyncio.run(get_coap_core())
