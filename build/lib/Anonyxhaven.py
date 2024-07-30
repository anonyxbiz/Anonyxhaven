# ./Anonyxhaven/Anonyxhaven.py
"""Internal_modules"""
import asyncio as io
from inspect import currentframe
from datetime import datetime
from functools import wraps
from typing import Callable
from os import environ
from os.path import exists, abspath, getsize
from mimetypes import guess_type
from secrets import token_urlsafe

"""External_modules"""
from aiohttp import web
from cryptography.fernet import Fernet

p = print

class Error(Exception):
    def __init__(self, message=None):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message

class Save:
    def __init__(self, db=None) -> None:
        self.db = db or "db.scarface"

    async def save_data(self, data: str):
        with open(self.db, "a", encoding="utf-8") as f:
            f.write(data + "\n")
        
class Log:
    def __init__(self) -> None:
        pass

    async def log(self, content=None, method=None, console_log=True):
        method = method or currentframe().f_back.f_code.co_name
        content = f"$ {method} [{str(datetime.now().time())}]: {str(content)}"

        for x in ['KeyboardInterrupt', 'ConnectionResetError', 'Cannot write to closing transport', 'Connection lost']:
            if x in content:
                console_log = False

        if self.logger_config['store_logs']:
            if self.logger_config['encrypt']:
                log_ = await self.safe_tool( [content] )
            else:
                log_ = content

            io.get_event_loop().create_task( Save().save_data( log_ ) )

        if console_log:
            p(content)

class Safe:
    def __init__(self) -> None:
        pass

    async def safe_tool(self, og: list | tuple) -> str | None:
        try:
            if isinstance(og, (list)):
                return Fernet(self.safe_key.encode()).encrypt(str(og[0]).encode("utf-8")).decode('utf-8')
            elif isinstance(og, (tuple)):
                return Fernet(self.safe_key.encode()).decrypt(str(og[0]).encode("utf-8")).decode('utf-8')
        except Exception as e:
            p(e)
        
class RecognizeFile:
    def __init__(self):
        pass

    async def recognize_file_simple(self, path):
        file_type, _ = guess_type(path)
        if not file_type:
            file_type = await self.accurate( path )

        return file_type

class Handlers:
    def __init__(self) -> None:
        self.app_routes = []
        self.hosts = ["localhost:8001", "127.0.0.1:8001"]
        self.headers = {
            'Server': self.app_name,
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(self), microphone=()',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        }
        self.valid_static_files = ['text/css', 'text/javascript', 'text/html', 'image/png', 'image/jpeg', 'image/jpg']

    async def before(self, request_id):
        request = self.requests[request_id]['request']
        ip = request.headers.get('X-Forwarded-For', None) or request.headers.get('X-Real-IP', None) or request.headers.get('Forwarded', None)
        await self.log(f"Request {request_id}: {ip or ''} @{request.path}")

        host, useragent = request.headers.get('Host', None), request.headers.get('User-Agent', None)
        if host not in self.hosts:
            raise Error('Host not allowed')

        for route_path, route_Handlers, route_methods in self.app_routes:
            if (tail := str(request.path)) == route_path:
                if request.method in route_methods:
                    return route_Handlers
                else:
                    raise Error('Method not allowed')
            
        raise Error('Unknown route')

    async def after(self, request_id):
        if isinstance(request_id, (str,)):
            if (request := self.requests[request_id])['response'] is not None and request['request_state'] != 'processed':
                for key, value in self.headers.items():
                    self.requests[request_id]['response'].headers[key] = value
                self.requests[request_id]['request_state'] = 'processed'
        else:
            for key, value in self.headers.items():
                request_id[0].headers[key] = value
            return request_id[0]
            
    async def gen(self, file: str, start: int, end: int, chunk_size=100):
        with open(file, 'rb') as f:
            f.seek(start)
            while start < end:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                start += len(chunk)
                yield chunk
                if start >= end:
                    break

    async def stream_file(self, request_id, file: str, chunk_size=1024):
        try:
            if not exists( (file := abspath(file)) ):
                raise FileNotFoundError
            
            file_size = getsize(file)
            if (range_header := self.requests[request_id]['request'].headers.get('Range', None)):
                byte_range = range_header.strip().split('=')[1]
                start, end = byte_range.split('-')
                start = int(start)
                end = int(end) if end else file_size - 1
            else:
                start = 0
                end = file_size - 1

            res = self.web.StreamResponse(
                status=206 if range_header else 200,
                headers={
                    'Content-Range': f'bytes {start}-{end}/{file_size}' if range_header else '',
                    'Accept-Ranges': 'bytes',
                    'Content-Length': str(end - start + 1),
                    'Content-Type': await self.recognize_file_simple(file)
                }
            )
            self.requests[request_id]['response'] = res
            await self.after(request_id)
            
            while True:
                try:
                    await self.requests[request_id]['response'].prepare(self.requests[request_id]['request'])
                    async for chunk in self.gen(file, start, end + 60, chunk_size=chunk_size):
                        if chunk:
                            await self.requests[request_id]['response'].write(chunk)
                        else:
                            self.requests[request_id]['response'] = self.web.json_response(status=200, data={'detail': 'End of chunks'})
                            break
                    break
                except Exception as e:
                    self.requests[request_id]['response'] = self.web.json_response(status=403, data={'detail': 'Something went wrong'})
                    break

        except FileNotFoundError:
            self.requests[request_id]['response'] = self.web.json_response(status=404, data={
                'detail': "The content you're looking for cannot be found on this server"
            })

        except PermissionError:
            self.requests[request_id]['response'] = self.web.json_response(status=403, data={'detail': "Access denied"})

        except Exception as e:
            await self.log(e)
            self.requests[request_id]['response'] = self.web.json_response(status=403, data={'detail': 'Something went wrong'})
        finally:
            return self.requests[request_id]['response']

    async def abort(self, msg=''):
        raise Error(msg)

class App(Handlers, Log, Safe, RecognizeFile):
    def __init__(self, host='0.0.0.0', port=8001, app_name='Anonyxhaven') -> None:
        self.host, self.port = host, port
        self.jobs = []
        self.requests = {}
        self.before_middlewares = []
        self.after_middlewares = []
        self.logger_config = {'store_logs': False, 'encrypt': False}
        self.safe_key = environ.get("safe_key", Fernet.generate_key())
        self.web = web
        self.app_name = app_name

        Log.__init__(self)
        Safe.__init__(self)
        RecognizeFile.__init__(self)
        Handlers.__init__(self)

    def add_before(self, middleware_func: Callable):
        self.before_middlewares.append(middleware_func)
        return middleware_func

    def add_after(self, middleware_func: Callable):
        self.after_middlewares.append(middleware_func)
        return middleware_func

    def routes(self, path, methods):
        def decorator(func):
            self.app_routes.append((path, func, methods))
            return func
        return decorator

    @staticmethod
    def set_request(func: Callable):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                request = args[0]
                while True:
                    request_id = str(token_urlsafe(4))
                    if request_id not in self.requests:
                        break

                self.requests[request_id] = {'request': request, 'request_state': 'unprocessed', 'id': request_id, 'response': None}

                if (route := await self.before(request_id)):
                    kwargs['request_id'] = request_id
                    self.requests[request_id]['route'] = route

            except Error as e:
                kwargs['error'] = e
            finally:
                return await func(self, *args, **kwargs)
        return wrapper

    @set_request
    async def handle_request(self, request, request_id=None, error=None):
        try:
            if error is not None: raise error

            if self.requests[request_id]['request_state'] == 'unprocessed':
                for middleware in self.before_middlewares:
                    if (_ := await middleware(request_id)) is not None:
                        self.requests[request_id]['response'] = _

                if self.requests[request_id]['response'] is None:
                    self.requests[request_id]['response'] = await self.requests[request_id]['route'](request_id)

                if self.requests[request_id]['response'] is not None:
                    for middleware in self.after_middlewares:
                        if (_ := await middleware(request_id)) is not None:
                            self.requests[request_id]['response'] = _

        except Error as e:
            error = self.web.json_response(status=403, data={'detail': str(e)})
        except Exception as e:
            await self.log(e)
            error = self.web.json_response(status=404, data={'detail': "Something went wrong"})
        finally:
            try:
                if error is not None:
                    response = await self.after([error])
                else:
                    await self.after(request_id)
                    if (response := self.requests[request_id]['response']) is not None:
                        # Avoid deleting streaming responses since they are active and yieding data to client
                        if '<StreamResponse' not in str(response):
                            del self.requests[request_id]

            except Exception as e:
                await self.log(e)


            return response

    async def run_app(self):
        runner = None
        server = self.web.Server(self.handle_request)
        runner = self.web.ServerRunner(server)
        await runner.setup()
        site = self.web.TCPSite(runner, self.host, self.port)
        await site.start()
        msg = f"=== Serving {self.app_name} on http://{self.host}:{self.port}/ ==="
        
        await self.log(msg)
        await io.sleep(100*3600)

    def run(self):
        try:
            io.run(self.run_app())
        except io.CancelledError:
            pass
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    pass
