# AnonyxHaven

**AnonyxHaven** is an asynchronous web framework built on top of Aiohttp, designed to implement custom security, performance, and efficiency for deploying Python applications. It offers a robust set of features for handling requests, managing security, and serving static and dynamic content in a performant manner.

## Features

- **Asynchronous Operations**: Utilizes `asyncio` for high-performance, non-blocking I/O operations.
- **Custom Security**: Integrates custom encryption and logging mechanisms to enhance application security.
- **Middleware Support**: Allows for easy addition of middleware functions to handle requests and responses.
- **Dynamic Content Serving**: Efficiently serves static files and supports partial content delivery for large files.
- **Flexible Routing**: Simplifies the creation and management of routes with custom handlers.

## Installation

Clone the repository and install the dependencies using pip:

```bash
pip install git+https://github.com/anonyxbiz/Anonyxhaven.git
```

## Basic Usage

### Creating an Application

Here's an example of how to create and run an application using **AnonyxHaven**:

```python
from Anonyxhaven import App
import asyncio as io
import random

app = App()

# Serve files
@app.routes('/favicon.ico', ['GET'])
async def route(request_id):
    io.get_event_loop().create_task( app.stream_file(request_id, './static/images/logo.png') )
    while (response := app.requests[request_id]['response']) is None:
        await io.sleep(0.1)

    return response

@app.routes('/watch', ['POST', 'GET'])
async def route(request_id):
    video_id = str(app.requests[request_id]['request'].query_string).replace('v=', '')

    io.get_event_loop().create_task( app.stream_file(request_id, f'./static/uploads/{video_id}.mp4', chunk_size=1024) )
    while (response := app.requests[request_id]['response']) is None:
        await io.sleep(0.1)

    return response

# Rest api
@app.routes('/', ['GET'])
async def route(request_id):
    _ = [' something', ' nothing']
    return app.web.json_response({'you_are': random.choice(_)})    

if __name__ == "__main__":
    app.run()

```

### Key Components

- **`App`**: Main application class that combines various components like logging, routing, and security.
- **`Save`**: Handles saving data to a file.
- **`Log`**: Provides logging functionality with optional encryption.
- **`Safe`**: Implements encryption and decryption methods.
- **`Grab`**: Utilities for grabbing request headers and IP addresses.
- **`RecognizeFile`**: Recognizes file types based on file extensions.
- **`Handlers`**: Manages request and response handling, including static file serving.

## Configuration

Set the `safe_key` environment variable to configure encryption:

```bash
export safe_key="your-encryption-key"
```

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request with your changes. Ensure to follow the coding style and include relevant tests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please contact [anonyxbiz@gmail.com].