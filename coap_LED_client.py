import asyncio
import argparse
from aiocoap import Context, Message
from aiocoap.numbers.codes import Code

async def send_post_request(uri, payload):
    """
    Send a POST request to the specified CoAP server URI with the given payload.
    
    Args:
        uri (str): The CoAP server URI (e.g., "coap://localhost:5683/test").
        payload (str): The payload to send in the POST request.
    """
    context = await Context.create_client_context()

    # Create the CoAP message
    request = Message(code=Code.POST, uri=uri, payload=payload.encode('utf-8'))

    try:
        # Send the request and wait for a response
        response = await context.request(request).response
        print(f"Response Code: {response.code}")
        print(f"Response Payload: {response.payload.decode('utf-8') if response.payload else '<Empty>'}")
    except Exception as e:
        print(f"Failed to send POST request: {e}")

async def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Send RGB values to a CoAP server.')
    parser.add_argument('red', type=int, help='Red color value (0-255)')
    parser.add_argument('green', type=int, help='Green color value (0-255)')
    parser.add_argument('blue', type=int, help='Blue color value (0-255)')
    args = parser.parse_args()

    # Validate the RGB values
    if not (0 <= args.red <= 255) or not (0 <= args.green <= 255) or not (0 <= args.blue <= 255):
        print("RGB values must be in the range 0-255.")
        return

    # Specify the CoAP server URI
    uri = "coap://[FDD5:419B:99E7:1:5656:D596:4AC8:7CCB]:5683/led"

    # Create the payload with the provided RGB values
    payload = f"""
                {{
                    "green" : "{args.green}",
                    "red" : "{args.red}",
                    "blue" : "{args.blue}"
                }}
                """
    
    # Send the POST request
    await send_post_request(uri, payload)

if __name__ == "__main__":
    asyncio.run(main())
