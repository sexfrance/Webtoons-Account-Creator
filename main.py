import aiofiles
import tls_client
import random
import string
import yaml
import asyncio
import re
import pytz
import threading
import ctypes

from functools import lru_cache
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, ALL_COMPLETED
from datetime import datetime, timedelta
from collections import deque
from time import time as timestamp
from contextlib import asynccontextmanager
from binascii import hexlify
from rsa import PublicKey, encrypt as rsae
from secrets import token_urlsafe
from logmagix import Logger, Home
from mailtmwrapper import MailTM
from random_header_generator import HeaderGenerator

home = Home("Webtoons Creator", align="center", credits="discord.cyberious.xyz")
log = Logger()
session = tls_client.Session(client_identifier="chrome_131", random_tls_extension_order=True)

total = 0
genStartTime = None

class TLSSessionManager:
    def __init__(self, pool_size: int = 10):
        self.pool_size = pool_size
        self.sessions = []
        self.retry_count = 3
        self.retry_delay = 1
        self._locks = {} 
        self._session_pool = []
        self._max_retries = 3
        
    def _get_lock(self):
        thread_id = threading.get_ident()
        if thread_id not in self._locks:
            self._locks[thread_id] = asyncio.Lock()
        return self._locks[thread_id]

    async def get_session(self) -> tls_client.Session:
        lock = self._get_lock()
        async with lock:
            if self._session_pool:
                return self._session_pool.pop()
            session = tls_client.Session(
                client_identifier="chrome_131",
                random_tls_extension_order=True
            )
            if not PROXYLESS:
                session.proxies = await proxy_dict()
            return session

    async def release_session(self, session: tls_client.Session):
        if len(self._session_pool) < self.pool_size:
            self._session_pool.append(session)

    async def request_with_retry(self, session: tls_client.Session, method: str, url: str, **kwargs) -> Optional[dict]:
        for attempt in range(self.retry_count):
            try:
                response = await asyncio.to_thread(
                    lambda: getattr(session, method)(url, **kwargs)
                )
                return response
            except Exception as e:
                if attempt == self.retry_count - 1:
                    raise
                await asyncio.sleep(self.retry_delay * (attempt + 1))
        return None

    async def cleanup(self):
        async with self._lock:
            self.sessions.clear()

session_manager = TLSSessionManager()

class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self._locks = {}

    def _get_lock(self):
        thread_id = threading.get_ident()
        if thread_id not in self._locks:
            self._locks[thread_id] = asyncio.Lock()
        return self._locks[thread_id]

    async def acquire(self):
        lock = self._get_lock()
        async with lock:
            now = datetime.now()
            while self.requests and self.requests[0] <= now - timedelta(seconds=self.time_window):
                self.requests.popleft()
            
            if len(self.requests) >= self.max_requests:
                sleep_time = (self.requests[0] + timedelta(seconds=self.time_window) - now).total_seconds()
                await asyncio.sleep(sleep_time)
            
            self.requests.append(now)

def update_title():
    try:
        global total

        title = f'discord.cyberious.xyz | Total: {total} | Time Elapsed: {round(timestamp() - genStartTime, 2)}s'
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception as e:
        pass

def run_in_new_loop(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

class AccountCreator:
    def __init__(self, config):
        self.config = config
        self.rate_limiter = RateLimiter(
            max_requests=config.get('RateLimit', {}).get('MaxRequests', 10),
            time_window=config.get('RateLimit', {}).get('TimeWindow', 60)
        )
        self.session_manager = TLSSessionManager(pool_size=config.get("Threads", 10))
        self.running = True
        self._thread_loops = {}
        self._lock = threading.Lock()
        self.session_pool = []
        self.max_retries = 2

    async def create_accounts_threaded(self):
        with ThreadPoolExecutor(max_workers=self.config.get("Threads", 10)) as executor:
            while self.running:
                futures = [
                    executor.submit(self._run_in_thread)
                    for _ in range(self.config.get("Threads", 10))
                ]
                
                done, _ = await asyncio.get_event_loop().run_in_executor(
                    None, 
                    lambda: wait(futures)
                )
                
                for future in done:
                    try:
                        if future.result():
                            log.success(f"Account created successfully")
                    except Exception as e:
                        log.failure(f"Thread error: {str(e)}")

    def _run_in_thread(self):
        try:
            loop = self._get_or_create_loop()
            return loop.run_until_complete(create_account(proxy_dict=loop.run_until_complete(proxy_dict())))
        except Exception as e:
            log.failure(f"Thread execution error: {str(e)}")
            return False

    def _get_or_create_loop(self):
        thread_id = threading.get_ident()
        with self._lock:
            if thread_id not in self._thread_loops:
                loop = asyncio.new_event_loop()
                self._thread_loops[thread_id] = loop
                asyncio.set_event_loop(loop)
            return self._thread_loops[thread_id]

    def stop(self):
        self.running = False
        with self._lock:
            for loop in self._thread_loops.values():
                try:
                    loop.stop()
                except:
                    pass
            self._thread_loops.clear()

@lru_cache(maxsize=100)
def get_headers():
    return HeaderGenerator()()

@asynccontextmanager
async def get_config():
    async with aiofiles.open("input/config.yml", "r") as config_file:
        content = await config_file.read()
        yield yaml.safe_load(content)

@asynccontextmanager
async def get_proxies():
    if PROXYLESS:
        yield []
    else:
        async with aiofiles.open("input/proxies.txt", "r") as f:
            content = await f.read()
            yield [line.strip() for line in content.splitlines() if line.strip()]

async def proxy_dict():
    async with get_proxies() as proxies:
        if not proxies:
            return None
        proxy = random.choice(proxies)
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}

async def save_account(email: str, password: str):
    async with aiofiles.open("output/accounts.txt", 'a') as f:
        await f.write(f"{email}:{password}\n")

async def generate_email():
    username = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=44))}"
    email = f"{username}@freesourcecodes.com"
    return email

def get_proxied_session():
    return tls_client.Session(client_identifier="chrome_131", random_tls_extension_order=True)
          
async def generate_password():
    password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/", k=16))
    return password

def chrlen( n: str) -> str:
    return chr(len(n))

async def encrypt(json: str, mail: str, pw: str):
    string = f"{chrlen(json['sessionKey'])}{json['sessionKey']}{chrlen(mail)}{mail}{chrlen(pw)}{pw}".encode()
    mod = int(json['nvalue'], 16)
    evl = int(json['evalue'], 16)
    pbk = PublicKey(evl, mod)
    out = rsae(string, pbk)
    return hexlify(out).decode('utf-8')

def handle_mailtm_response(func=None, *, retries=3, base_delay=2):
    if func is None:
        return lambda f: handle_mailtm_response(f, retries=retries, base_delay=base_delay)
        
    async def wrapper(*args, **kwargs):
        for attempt in range(retries):
            try:
                response = func(*args, **kwargs)
                if response == 429:
                    delay = base_delay * (attempt + 1)
                    log.warning(f"Rate limited by MailTM, waiting {delay}s...")
                    await asyncio.sleep(delay)
                    continue
                if response == 401:
                    log.warning("Invalid MailTM token, recreating...")
                    if 'token' in kwargs:
                        if len(args) >= 2:
                            new_token = await create_token_request(args[0], args[1])
                            if new_token:
                                kwargs['token'] = new_token
                                continue
                    return None
                return response
            except Exception as e:
                log.failure(f"MailTM error: {str(e)}")
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(base_delay * (attempt + 1))
        return None
    return wrapper

@handle_mailtm_response
def create_mail_request(email: str, password: str, proxy_dict: dict = None):
    return MailTM(proxy_dict=proxy_dict).create_account(email, password)

@handle_mailtm_response
def get_messages_request(token: str, proxy_dict: dict = None):
    return MailTM(token, proxy_dict=proxy_dict).get_messages()

@handle_mailtm_response
def get_message_request(token: str, message_id: str, proxy_dict: dict = None):
    return MailTM(token, proxy_dict).get_message_by_id(message_id)

@handle_mailtm_response
def create_token_request(email: str, password: str):
    return MailTM().create_token(email, password)

async def create_mail(email: str, password: str, proxy_dict: dict = None):
    response = await create_mail_request(email, password, proxy_dict)
    
    if DEBUG:
        log.debug(f"MailTM response: {response}")

    if response and isinstance(response, dict):
        account_id = response.get('id')
        if account_id:
            return account_id, email
    return None, None

async def get_email_message_id(token: str, max_retries: int = 3, proxy_dict: dict = None, email: str = None, password: str = None):
    if DEBUG:
        log.debug(f"Checking mailbox")
    
    for attempt in range(max_retries):
        if attempt > 0:
            await asyncio.sleep(1)
        messages = await get_messages_request(token=token, proxy_dict=proxy_dict)
        
        if messages == 401:
            if email and password:
                token = await create_token_request(email, password)
                if not token:
                    return None
                continue
            return None

        if not isinstance(messages, list):
            log.failure(f"Unexpected type for messages: {type(messages)}. Messages: {messages}")
            continue
    
        if DEBUG:
            log.debug(f"Messages received: {messages}")

        if messages:
            for message in messages:
                msg_id = message.get('id')
                subject = message.get('subject')
                if subject and '[WEBTOON] Verification Email' in subject:
                    return msg_id
        
        log.info(f"No verification email found, attempt {attempt + 1}/{max_retries}")
    
    return None

async def get_verification_link(token: str, message_id: str, proxy_dict: dict = None):
    message = await get_message_request(token, message_id, proxy_dict)
    
    if not message:
        log.failure("Failed to retrieve message. Message might be None.")
        return None

    content = message.get('text', '')
    if not content and 'html' in message and message['html']:
        content = message['html'][0]

    try:
        link_match = re.search(r'https?://[^\s\]]+email-verification[^\s\]]+', content)
        if link_match:
            verification_link = link_match.group(0)
            log.success(f"Verification link found: {verification_link}")
            return verification_link
        else:
            log.warning("Verification link not found in the message content.")
            return None
    except Exception as e:
        log.failure(f"Error extracting verification link: {e}")
        return None
    
async def verify_email(verify_link: str):
    session = await session_manager.get_session()
    try:
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
        }
        verify_link = verify_link.replace("m.webtoons.com", "www.webtoons.com")
        verify_link = verify_link + "&webtoon-platform-redirect=true"

        response = await session_manager.request_with_retry(
            session,
            'get',
            verify_link,
            headers=headers
        )
        cookies = dict(response.cookies)
        return cookies.get("email_vr") == "EMAIL_JOIN"
    finally:
        await session_manager.release_session(session)

async def get_key():
    session = await session_manager.get_session()
    try:
        response = await session_manager.request_with_retry(
            session,
            'get',
            "https://www.webtoons.com/member/login/rsa/getKeys"
        )
        return response.json()
    finally:
        await session_manager.release_session(session)

async def getcookies():
    return {
        "wtu"                : token_urlsafe(24),
        "locale"             : "en",
        "needGDPR"           : "true",
        "needCCPA"           : "false",
        "needCOPPA"          : "false",
        "countryCode"        : "RO",
        "timezoneOffset"     : "+3",
        "ctZoneId"           : "Europe/Bucharest",
        "wtv"                : "1",
        "wts"                : str(int(timestamp() * 1000)),
        "__cmpconsentx47472" : f"{token_urlsafe(2)}_{token_urlsafe(3)}_{token_urlsafe(25)}",
        "__cmpcccx47472"     : token_urlsafe(18),
        "_fbp"               : "fb.1.1684479996310.2019224647",
        "_scid"              : "858a934e-433c-4e07-b4c3-c1a1b9becc34",
        "_gid"               : "GA1.2.1016427982.1684479996",
        "_tt_enable_cookie"  : "1",
        "_ttp"               : "2dlVmcQxdz_oQTW_6zMA2eNlFy3",
        "_scid_r"            : "858a934e-433c-4e07-b4c3-c1a1b9becc34",
        "_ga"                : "GA1.1.1939944414.1684479996",
        "_ga_ZTE4EZ7DVX"     : "GS1.1.1684486049.2.0.1684486049.60.0.0",
    }

async def create_account(email: str = None, password: str = None, username: str = None, proxy_dict: dict = None):
    session = await session_manager.get_session()
    try:
        if password is None:
            password = await generate_password()
        if email is None:
            email = await generate_email()
            account_data = await create_mail(email, password, proxy_dict)
            if account_data is None:
                return False
        if username is None:
            username = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

        log.info(f"Creating account with email: {email}")
        cookies = await getcookies()
        
        key = await get_key()
        
        headers = get_headers()
        
        headers.update({
            'Host': 'www.webtoons.com',
            'Origin': 'https://www.webtoons.com',
            'Referer': 'https://www.webtoons.com/member/join?loginType=EMAIL',
            'X-requested-with': 'XMLHttpRequest',
        })

        data = {
            'loginType': 'EMAIL',
            'nickname': username,
            'encnm': key['keyName'],
            'encpw': await encrypt(key, email, password),
            'zoneId': random.choice(pytz.all_timezones),
            'emailEventAlarm': 'true',
            'v': '3',
            'language': 'en',
            'year': str(random.randint(1980, 2005)),
            'month': str(random.randint(1, 12)),
            'dayOfMonth': str(random.randint(1, 28))
        }

        temp_session = get_proxied_session()
        if not PROXYLESS:
            temp_session.proxies = proxy_dict
        
        response = await session_manager.request_with_retry(
            session,
            'post',
            'https://www.webtoons.com/member/join/doJoinById',
            cookies=cookies,
            headers=headers,
            data=data
        )

        if response.json()['success'] == True:
            log.success(f"Successfully created account for {email}")
            log.info(f"Verifying email...")
            
            for _ in range(2):
                token = await create_token_request(email, password)
                if token:
                    break
                await asyncio.sleep(1)
                
            if not token:
                log.failure("Failed to create MailTM token after all retries")
                return False

            if DEBUG:
                log.debug(f"Credentials: {email}, {password}")
                log.debug(f"Token: {token}")

            message_id = await get_email_message_id(token, proxy_dict=proxy_dict, email=email, password=password)
            if message_id:    
                verify_link = await get_verification_link(token, message_id, proxy_dict)
                if verify_link and await verify_email(verify_link):
                    log.success("Email verified successfully")
                    await save_account(email, password)
                    global total
                    total += 1
                    update_title()
                    return True
            
            log.failure("Failed to verify email")
            return False
        else:
            log.failure("Failed to create account, trying again...")
            return False
    finally:
        await session_manager.release_session(session)

async def main():
    try:
        global genStartTime
        genStartTime = timestamp()
        
        async with get_config() as config:
            global DEBUG, PROXYLESS, THREADS
            DEBUG = config.get("Debug", False)
            PROXYLESS = config.get("Proxyless", True)
            THREADS = config.get("Threads", 10)

            creator = AccountCreator(config)
            
            async with get_proxies() as proxies:
                if proxies and not PROXYLESS:
                    home.adinfo1 = f"Loaded proxies: {len(proxies)}"
                else:
                    home.adinfo1 = "Mode: Proxyless"

            home.adinfo2 = f"Debug: {'ON' if DEBUG else 'OFF'}"
            home.display()

            try:
                await creator.create_accounts_threaded()
            except KeyboardInterrupt:
                log.info("Shutting down gracefully...")
                creator.stop()
            except Exception as e:
                log.failure(f"Error in main loop: {str(e)}")
                if DEBUG:
                    raise
    finally:
        await cleanup_sessions()

async def cleanup_sessions():
    try:
        await session_manager.cleanup()
    except:
        pass

if __name__ == "__main__":
    asyncio.run(main())