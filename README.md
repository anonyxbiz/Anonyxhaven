# AnonyxHaven

**AnonyxHaven** is a high-performance, asynchronous web framework built on top of Aiohttp, designed to offer custom security, efficiency, and flexibility for Python applications. It provides a comprehensive suite of features for managing requests, enhancing security, and serving both static and dynamic content efficiently.

## Features

- **Asynchronous Operations**: Leverages `asyncio` for non-blocking I/O operations, enabling efficient handling of concurrent requests.
- **Custom Security**: Integrates advanced encryption and logging mechanisms to bolster application security.
- **Middleware Support**: Easily add and manage middleware functions for processing requests and responses.
- **Dynamic Content Serving**: Supports efficient serving of static files and partial content delivery for large files.
- **Flexible Routing**: Simplifies the creation and management of routes with customizable handlers.
- **Rate Limiting**: Protect your application from abuse with configurable rate limiting based on IP addresses.
- **Advanced Logging**: Optionally encrypt logs for secure storage.

## Installation

You can install **AnonyxHaven** directly from GitHub using pip:

```bash
pip install git+https://github.com/anonyxbiz/Anonyxhaven.git
```

## Basic Usage

### Creating an Application

Here's how to create and run a simple application with **AnonyxHaven**:

```python
from Anonyxhaven import App
import asyncio as io
import random

app = App()

# Serve favicon
@app.routes('/favicon.ico', ['GET'])
async def favicon(request_id):
    io.get_event_loop().create_task(app.stream_file(request_id, './static/images/logo.png'))
    while (response := app.requests[request_id]['response']) is None:
        await io.sleep(0.1)
    return response

# Stream video
@app.routes('/watch', ['POST', 'GET'])
async def watch(request_id):
    video_id = str(app.requests[request_id]['request'].query_string).replace('v=', '')
    io.get_event_loop().create_task(app.stream_file(request_id, f'./static/uploads/{video_id}.mp4', chunk_size=1024))
    while (response := app.requests[request_id]['response']) is None:
        await io.sleep(0.1)
    return response

# REST API endpoint
@app.routes('/', ['GET'])
async def home(request_id):
    _ = ['something', 'nothing']
    return app.web.json_response({'you_are': await io.to_thread(random.choice, _)})    

if __name__ == "__main__":
    app.run()
```

### Key Components

- **`App`**: The core application class that integrates routing, middleware, logging, and security features.
- **`Save`**: Manages file saving operations.
- **`Log`**: Provides logging functionality with optional encryption for secure log management.
- **`Safe`**: Implements encryption and decryption methods for securing data.
- **`Grab`**: Utilities for extracting request headers and IP addresses.
- **`RecognizeFile`**: Identifies file types based on extensions.
- **`Handlers`**: Manages request and response processing, including static file serving.

## Configuration

Set the `safe_key` environment variable to enable encryption:

```bash
export safe_key="your-encryption-key"
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your changes.
3. Make your changes and commit them with descriptive messages.
4. Push your changes and create a pull request.

Please adhere to the coding style and include relevant tests with your pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or issues, please contact [anonyxbiz@gmail.com].
