"""Shared atomic rate limits and quotas, with explicit single-instance fallback."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class LocalLimiter:
    """Single-process fixed-window limiter. Never suitable for multi-instance mode."""
    def __init__(self):
        self.lock=Lock(); self.requests=defaultdict(deque); self.daily=defaultdict(deque); self.global_daily=deque()

    def allow(self, identity: str, *, per_minute: int, per_day: int, global_per_day: int) -> tuple[bool,str|None]:
        now=time.time()
        with self.lock:
            minute=self.requests[identity]
            while minute and minute[0]<=now-60: minute.popleft()
            if len(minute)>=per_minute: return False,"rate_limit_exceeded"
            day=self.daily[identity]
            while day and day[0]<=now-86400: day.popleft()
            while self.global_daily and self.global_daily[0]<=now-86400: self.global_daily.popleft()
            if len(day)>=per_day: return False,"daily_client_quota_exceeded"
            if len(self.global_daily)>=global_per_day: return False,"daily_scan_quota_exceeded"
            minute.append(now); day.append(now); self.global_daily.append(now)
            return True,None


class RedisLimiter:
    """Atomic cross-worker limits implemented using Redis Lua and rolling sorted sets."""
    _SCRIPT="""
local now=tonumber(ARGV[1]); local member=ARGV[2]; local minute=tonumber(ARGV[3]); local userday=tonumber(ARGV[4]); local globalday=tonumber(ARGV[5]);
local function prune(k,window) redis.call('ZREMRANGEBYSCORE',k,'-inf',now-window) end
prune(KEYS[1],60); prune(KEYS[2],86400); prune(KEYS[3],86400)
if redis.call('ZCARD',KEYS[1])>=minute then return 1 end
if redis.call('ZCARD',KEYS[2])>=userday then return 2 end
if redis.call('ZCARD',KEYS[3])>=globalday then return 3 end
redis.call('ZADD',KEYS[1],now,member); redis.call('ZADD',KEYS[2],now,member); redis.call('ZADD',KEYS[3],now,member)
redis.call('EXPIRE',KEYS[1],120); redis.call('EXPIRE',KEYS[2],90000); redis.call('EXPIRE',KEYS[3],90000); return 0
"""
    def __init__(self,url: str,key_prefix: str="sitesentry"):
        import redis
        self.client=redis.Redis.from_url(url,decode_responses=True,socket_connect_timeout=2,socket_timeout=2)
        self.key_prefix=key_prefix.rstrip(":")
        self.client.ping()

    def allow(self,identity: str,*,per_minute: int,per_day: int,global_per_day: int)->tuple[bool,str|None]:
        now=time.time(); member=f"{now}:{__import__('uuid').uuid4().hex}"
        result=self.client.eval(self._SCRIPT,3,f"{self.key_prefix}:minute:{identity}",f"{self.key_prefix}:day:{identity}",f"{self.key_prefix}:global:day",now,member,per_minute,per_day,global_per_day)
        return (True,None) if result==0 else (False,{1:"rate_limit_exceeded",2:"daily_client_quota_exceeded",3:"daily_scan_quota_exceeded"}[int(result)])
