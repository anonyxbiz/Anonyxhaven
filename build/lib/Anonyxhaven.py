# ./Anonyxhaven/Anonyxhaven.py
"""
# AnonyxHaven
AnonyxHaven is an asynchronous web framework built on top of Aiohttp, designed to implement custom security, performance, and efficiency for deploying production-ready Python applications. It offers a robust set of features for handling requests, managing security, and serving static and dynamic content in a performant manner.
"""
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

        for x in ['KeyboardInterrupt', 'ConnectionResetError', 'Cannot write to closing transport', 'Connection lost', 'Cannot call write()']:
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
        return file_type

class FileHandlers:
    def __init__(self) -> None:
        pass

    async def stream_file(self, request_id, file: str, chunk_size=1024):
        try:
            if not exists( (file := abspath(file)) ):
                raise Error("The content you're looking for cannot be found on this server")
            
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

            f = open(file, 'rb')
            self.requests[request_id]['open_files'] = [f]

            # prepare request here
            await self.requests[request_id]['response'].prepare(self.requests[request_id]['request'])

            while True:
                try:
                    f.seek(start)
                    while start < end + 10:
                        chunk = f.read(chunk_size)
                        if chunk:
                            start += len(chunk)
                            await self.requests[request_id]['response'].write(chunk)
                            if start >= end:
                                break                               
                        else:
                            break
                    break
                except Exception as e:
                    break

        except Error as e:
            self.requests[request_id]['response'] = self.web.json_response(status=403, data={'detail': str(e)})
        except Exception as e:
            await self.log(e)
        finally:
            try:
                if (files := self.requests[request_id].get('open_files', None)):
                    for file in files:
                        file.close()

                return self.requests[request_id]['response']
            except Exception as e: pass

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
        self.request_timeout_management_timeout = 60
 
    async def request_timeout_management(self, request_id, expiry=None):
        try:
            await io.sleep(expiry or self.request_timeout_management_timeout)
            del self.requests[request_id]
        except KeyError: pass

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
            self.jobs.append(io.get_event_loop().create_task( self.request_timeout_management(request_id) ))
            if (request := self.requests[request_id])['response'] is not None and request['request_state'] != 'processed':
                for key, value in self.headers.items():
                    self.requests[request_id]['response'].headers[key] = value
                self.requests[request_id]['request_state'] = 'processed'
                return self.requests[request_id]['response']
        else:
            for key, value in self.headers.items():
                request_id[0].headers[key] = value

            return request_id[0]

    async def abort(self, msg=''):
        raise Error(msg)

class App(Handlers, Log, Safe, RecognizeFile, FileHandlers):
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
        self.cookie_auth = False
        self.configs = {}

        Log.__init__(self)
        Safe.__init__(self)
        RecognizeFile.__init__(self)
        Handlers.__init__(self)
        FileHandlers.__init__(self)

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
                request_id = None
                request = args[0]

                if request_id is None:
                    while True:
                        request_id = str(token_urlsafe(16))
                        if request_id not in self.requests:
                            break
                        else:
                            await io.sleep(0.01)               
                r_data = {
                    'request': request,
                    'request_state': 'unprocessed',
                    'id': request_id,
                    'initiated': str(datetime.now()),
                    'response': None
                }

                self.requests[request_id] = r_data

                if (route := await self.before(request_id)):
                    kwargs['request_id'] = request_id
                    self.requests[request_id]['route'] = route

            except Error as e:
                kwargs['error'] = e
            except Exception as e:
                await self.log(e)
            finally:
                return await func(self, *args, **kwargs)
        return wrapper

    @set_request
    async def handle_request(self, request, request_id=None, error=None):
        try:
            if error is not None: raise error

            if self.requests[request_id]['request_state'] == 'unprocessed':
                if self.before_middlewares != []:
                    for middleware in self.before_middlewares:
                        if (_ := await middleware(request_id)) is not None:
                            self.requests[request_id]['response'] = _

                if self.requests[request_id]['response'] is None:
                    self.requests[request_id]['response'] = await self.requests[request_id]['route'](request_id)

                if self.after_middlewares != []:
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
                    response = await self.after(request_id)
            except:
                pass
            finally:
                return response

    async def finalize(self):
        if self.jobs != []:
            for job in self.jobs:
                job.cancel()

            for job in self.jobs:
                try:
                    await job
                except io.CancelledError:
                    pass

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
        except ConnectionResetError:
            pass
        except ConnectionError:
            pass
        except io.CancelledError:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            io.run(self.finalize())
            

if __name__ == "__main__":
    pass
