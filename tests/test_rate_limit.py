from __future__ import annotations

from rate_limit import LocalLimiter, RedisLimiter


def test_local_limiter_enforces_minute_and_daily_caps():
    limiter=LocalLimiter()
    assert limiter.allow("u",per_minute=1,per_day=5,global_per_day=5)==(True,None)
    assert limiter.allow("u",per_minute=1,per_day=5,global_per_day=5)==(False,"rate_limit_exceeded")


def test_redis_limiter_uses_atomic_script_and_shared_keys(monkeypatch):
    import redis
    class FakeRedis:
        def __init__(self): self.call=None
        def ping(self): return True
        def eval(self,*args): self.call=args; return 0
    fake=FakeRedis()
    monkeypatch.setattr(redis,"Redis",type("Factory",(),{"from_url":staticmethod(lambda *a,**k:fake)}))
    limiter=RedisLimiter("redis://localhost/0")
    allowed,reason=limiter.allow("identity",per_minute=3,per_day=4,global_per_day=8)
    assert allowed and reason is None
    assert fake.call[1]==3 and "sitesentry:global:day" in fake.call
