# ./Anonyxhaven/Anonyxhaven.py
"""
# AnonyxHaven
AnonyxHaven is an asynchronous web framework built on top of Aiohttp, designed to implement custom security, performance, and efficiency for deploying production-ready Python applications. It offers a robust set of features for handling requests, managing security, and serving static and dynamic content in a performant manner.
"""
"""Internal_modules"""
import asyncio as io, os, random
from inspect import currentframe
from datetime import datetime
from functools import wraps
from typing import Callable
from os import environ
from os.path import exists, abspath, getsize
from mimetypes import guess_type
from secrets import token_urlsafe

"""External_modules"""
from aiohttp import web, ClientSession
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
        self.block_bad_hosts = False
 
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
        if self.block_bad_hosts:
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

class Rate_limiter:
    def __init__(self, life_span=10, max_rqs_per_life_span=30, IP_INFO_API_KEY=None) -> None:
        self.ip_s = {}
        self.life_span = life_span
        self.max_rqs_per_life_span = max_rqs_per_life_span
        self.cool_down = life_span
        self.flagged = ['vps', 'tor', 'exit', 'node', 'relay']
        self.IP_INFO_API_KEY = IP_INFO_API_KEY or environ.get('ip_info_key', None)

    async def identification(self, ip):
        async with ClientSession() as client:
            async with client.get(f"https://ipinfo.io/{ip}?token={self.IP_INFO_API_KEY}") as r:
                if r.status >= 400:
                    return
                
                r = await r.json()
                check = r.get('hostname', None) or r.get('org', None)
                
                if not check:
                    return
                
                for i in self.flagged:
                    if i in check:
                        await self.abort("Hey there! Using a proxy or Tor, huh? Sorry, but sneaky activities aren't allowed around here.")

    async def rate_limiting(self, ip):
        try:
            difference = (datetime.now() - self.ip_s[ip]['stamp']).total_seconds()
            last_hit_difference = (datetime.now() - self.ip_s[ip]['last_hit']).total_seconds()
            if (hits := self.ip_s[ip]['hits']) >= self.max_rqs_per_life_span:
                if difference <= self.life_span:
                    self.ip_s[ip]['nerfed_times'] += 1

                    return (False, f'Whoa there! You\'re hitting it like a bodybuilder on a caffeine spree. Slow your roll for {self.ip_s[ip]["cooldown"]} seconds or you might just short-circuit the server and annoy everyone (including yourself). Let\'s keep it cool and calm, alright?')

                else:
                    if difference >= self.life_span:
                        if last_hit_difference <= self.ip_s[ip]["cooldown"]:
                            time_asked_to_chill = self.ip_s[ip]["cooldown"]
                            cool_down_increment = random.randint(0, 10)

                            # to make their wait time count, deduct the time they've waited
                            self.ip_s[ip]["cooldown"] += cool_down_increment

                            self.ip_s[ip]["cooldown"] = self.ip_s[ip]["cooldown"] - last_hit_difference

                            response = (False, f'Ayee, you\'re sending requests faster than a squirrel on an espresso binge! I asked you to chill for {time_asked_to_chill} seconds, but you\'ve only managed to cool down for {last_hit_difference} seconds. So now, I\'m slamming the brakes even harder, get ready for another {self.ip_s[ip]["cooldown"]} seconds of downtime. Slow down, grab a coffee, and give us all a breather. If you don\'t, the wait time will become a real marathon!')

                            return response
                        else:
                            self.ip_s[ip]['stamp'] = datetime.now()
                            self.ip_s[ip]['hits'] = 0
                            self.ip_s[ip]['cooldown'] = self.cool_down

                    if self.ip_s[ip]['nerfed_times'] >= 1:
                        self.ip_s[ip]['nerfed_times'] = 0

                    return (True, '')
    
            return (True, '')

        except (Exception) as e:
            await self.log(e)

    async def stream_dynamic_file(self, request_id, file: str, chunk_size=1024, args=None):
        try:
            request = self.requests[request_id]['request']

            if not os.path.exists( (file := os.path.abspath(file)) ):
                return self.web.json_response(status=403, detail="The content you're looking for cannot be found on this server")

            response = self.web.StreamResponse(
                headers={
                    'Content-Type': await self.recognize_file_simple(file)
                }
            )
            self.requests[request_id]['response'] = response
            await self.after(request_id)

            await response.prepare(request)

            chunks = b''

            f = open(file, 'rb')
            while True:
                try:
                    chunk = f.read(chunk_size)
                    if chunk:
                        chunks += chunk
                        chunk = chunks.decode('utf-8')

                        for key, val in args.items():
                            chunk = chunk.replace(key, val)
                        
                        chunk = chunk.encode()
                        if isinstance(chunk, (bytes, bytearray)):
                            await response.write(chunk)
                            chunks = b''
                    else:
                        await response.write_eof()
                        break

                except (UnicodeEncodeError, UnicodeWarning, UnicodeTranslateError, UnicodeDecodeError):
                    pass
                except Exception as e:
                    p(e)

        except Exception as e:
            p(e)
        finally:
            f.close()

            return response

    async def app_defender(self, request_id):
        request = self.requests[request_id]['request']

        if (ip := request.headers.get('X-Forwarded-For', None) or request.headers.get('X-Real-IP', None) or request.headers.get('Forwarded', None)) is None:
            ip = f'127.0.0.1:{self.port}'

        host, useragent = request.headers.get('Host', None), request.headers.get('User-Agent', None)
        
        if ip not in self.ip_s:
            await self.identification(ip)
            self.ip_s[ip] = {
                'host': host,
                'useragent': useragent,
                'hits': 1,
                'stamp': datetime.now(),
                'nerfed_times': 0,
                'last_hit': datetime.now(),
                'cooldown': self.cool_down
            }
            return None
        
        else:
            if self.ip_s[ip]['host'] != host:
                await self.abort('Whoa there! It seems you\'re trying to do something a bit dodgy. Just a friendly reminder: messing with credentials is both illegal and dramatic.')

            limit_status = await self.rate_limiting(ip)
            self.ip_s[ip]['last_hit'] = datetime.now()

            if not limit_status [0]:
                args = {
                    '_page_header_': 'Rate limit',
                    '_page_context_': limit_status[1],
                    '_app_name_': 'Anonyx Tools',
                }

                response = await self.stream_dynamic_file(request_id, './static/page/rate_limits.html', args=args)
                return response
            else:
                self.ip_s[ip]['hits'] += 1
                return None

class App(Handlers, Log, Safe, RecognizeFile, FileHandlers, Rate_limiter):
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
        Rate_limiter.__init__(self)

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