"""
LLM Manager — health-aware Ollama relay for the A2A Security Lab.

All configured Ollama endpoints (remote GPUs + local) are treated as a
flat ordered list.  Requests are routed to the healthiest available
service.  Put the local Ollama URL last in PRIMARY_LLM_URLS so it
naturally serves as the fallback when all remote machines are down.

Env example:
  PRIMARY_LLM_URLS=http://remote-ollama.example.com:11434,http://172.20.0.6:11434
"""

import os
import requests
import logging
import time
import random
import threading
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
from dataclasses import dataclass
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ── Load balancing strategy ─────────────────────────────────────────────

class LoadBalancingStrategy(Enum):
    PRIORITY = "priority"
    ROUND_ROBIN = "round_robin"
    HEALTH_BASED = "health_based"
    RANDOM = "random"
    FASTEST_FIRST = "fastest_first"
    SMART_PERFORMANCE = "smart_performance"


# ── Per-service health tracking ─────────────────────────────────────────

@dataclass
class LLMService:
    """A single Ollama endpoint with health tracking."""
    url: str
    enabled: bool = True
    healthy: bool = True
    last_health_check: float = 0
    consecutive_failures: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    average_response_time: float = 0
    last_response_time: float = 0
    health_check_response_time: float = 0
    api_key: Optional[str] = None

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 100.0
        return (self.successful_requests / self.total_requests) * 100

    @property
    def health_score(self) -> float:
        if not self.enabled or not self.healthy:
            return 0.0
        success_score = self.success_rate
        max_gen_time = 30.0
        speed_score = (
            50.0 if self.average_response_time == 0
            else max(0, 100 - (self.average_response_time / max_gen_time) * 100)
        )
        max_hc_time = 5.0
        hc_score = (
            50.0 if self.health_check_response_time == 0
            else max(0, 100 - (self.health_check_response_time / max_hc_time) * 100)
        )
        return (success_score * 0.4) + (speed_score * 0.5) + (hc_score * 0.1)


# ── LLM Manager ─────────────────────────────────────────────────────────

class LLMManager:
    """
    Health-aware Ollama relay.  All configured URLs are peers in one flat
    list — no separate "fallback" concept.
    """

    def __init__(self):
        self._lock = Lock()
        self._rr_index = 0

        # ── Service list (comma-separated URLs) ──
        urls_str = os.getenv("PRIMARY_LLM_URLS", "")
        urls = [u.strip() for u in urls_str.split(",") if u.strip()]

        keys_str = os.getenv("PRIMARY_LLM_API_KEYS", "")
        keys = [k.strip() for k in keys_str.split(",") if k.strip()] if keys_str else []

        self.services: List[LLMService] = []
        for i, url in enumerate(urls):
            key = keys[i] if i < len(keys) else (keys[0] if keys else None)
            self.services.append(LLMService(url=url, enabled=True, api_key=key))

        # ── Tunables ──
        self.request_timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))

        strategy_str = os.getenv("LOAD_BALANCING", "smart_performance")
        self.load_balancing = LoadBalancingStrategy(strategy_str)

        self.health_check_interval = int(os.getenv("HEALTH_CHECK_INTERVAL", "300"))
        self.health_check_timeout = int(os.getenv("HEALTH_CHECK_TIMEOUT", "5"))
        self.max_consecutive_failures = int(os.getenv("MAX_CONSECUTIVE_FAILURES", "3"))
        self.fast_health_check = os.getenv("FAST_HEALTH_CHECK", "true").lower() == "true"

        logger.info(f"LLM Manager initialised — {len(self.services)} service(s)")
        for i, s in enumerate(self.services):
            logger.info(f"  [{i}] {s.url}")
        logger.info(f"  Load balancing: {self.load_balancing.value}")

        self._start_health_monitor()

    # ── Health checks ───────────────────────────────────────────────────

    def _check_health(self, svc: LLMService, timeout: int = None) -> bool:
        if timeout is None:
            timeout = self.health_check_timeout
        try:
            start = time.time()
            hdrs = {"Content-Type": "application/json"}
            if svc.api_key:
                hdrs["Authorization"] = f"Bearer {svc.api_key}"
            resp = requests.get(f"{svc.url}/api/tags", headers=hdrs, timeout=timeout)
            elapsed = time.time() - start
            with self._lock:
                svc.health_check_response_time = elapsed
                svc.last_health_check = time.time()
                if resp.status_code == 200:
                    svc.healthy = True
                    svc.consecutive_failures = 0
                    logger.info(f"✅ Health OK  {svc.url}  ({elapsed:.3f}s)")
                    return True
                svc.healthy = False
                svc.consecutive_failures += 1
                logger.info(f"❌ Health FAIL {svc.url}  HTTP {resp.status_code}")
                return False
        except Exception as exc:
            with self._lock:
                svc.healthy = False
                svc.consecutive_failures += 1
                svc.last_health_check = time.time()
            logger.info(f"❌ Health FAIL {svc.url}  {exc}")
            return False

    def _fast_check_all(self) -> List[LLMService]:
        if not self.services:
            return []
        with ThreadPoolExecutor(max_workers=min(len(self.services), 10)) as pool:
            futures = {
                pool.submit(self._check_health, svc, self.health_check_timeout): svc
                for svc in self.services if svc.enabled
            }
            healthy = []
            for fut in as_completed(futures, timeout=self.health_check_timeout + 2):
                try:
                    if fut.result():
                        healthy.append(futures[fut])
                except Exception:
                    pass
        return healthy

    def _ordered_services(self) -> List[LLMService]:
        """Return services ordered by the load-balancing strategy."""
        healthy = (
            self._fast_check_all() if self.fast_health_check
            else [s for s in self.services if s.enabled and s.healthy]
        )
        if not healthy:
            logger.warning("No healthy services — trying all enabled")
            return [s for s in self.services if s.enabled]

        strat = self.load_balancing
        if strat == LoadBalancingStrategy.PRIORITY:
            # Preserve original env list order — the operator's intended
            # priority.  _fast_check_all returns in completion order, so
            # re-sort by each service's position in self.services.
            svc_order = {id(s): i for i, s in enumerate(self.services)}
            healthy.sort(key=lambda s: svc_order.get(id(s), 999))
        elif strat == LoadBalancingStrategy.HEALTH_BASED:
            healthy.sort(key=lambda s: s.health_score, reverse=True)
        elif strat == LoadBalancingStrategy.FASTEST_FIRST:
            healthy.sort(key=lambda s: s.average_response_time or float("inf"))
        elif strat == LoadBalancingStrategy.SMART_PERFORMANCE:
            def _score(s):
                if s.total_requests == 0:
                    return 50.0
                penalty = min(s.average_response_time or 0, 60) / 60 * 50
                bonus = s.success_rate / 100 * 30
                return 100 - penalty + bonus
            healthy.sort(key=_score, reverse=True)
        elif strat == LoadBalancingStrategy.RANDOM:
            random.shuffle(healthy)
        elif strat == LoadBalancingStrategy.ROUND_ROBIN:
            with self._lock:
                idx = self._rr_index % len(healthy)
                healthy = healthy[idx:] + healthy[:idx]
                self._rr_index += 1
        return healthy

    def _start_health_monitor(self):
        def _loop():
            while True:
                try:
                    time.sleep(self.health_check_interval)
                    for svc in self.services:
                        if svc.enabled:
                            self._check_health(svc)
                except Exception as exc:
                    logger.error(f"Health monitor error: {exc}")
        threading.Thread(target=_loop, daemon=True).start()
        logger.info("Background health monitor started")

    # ── Relay ───────────────────────────────────────────────────────────

    def relay_request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_override: Optional[int] = None,
    ) -> Tuple[int, dict, bytes]:
        """
        Relay an Ollama API request to the best available service.

        Returns (status_code, response_headers, response_body).
        Raises Exception only when every service has failed.
        """
        timeout = timeout_override or self.request_timeout
        ordered = self._ordered_services()
        if not ordered:
            raise Exception("No LLM services configured or enabled")

        last_err = None
        for i, svc in enumerate(ordered):
            logger.info(f"📞 [{i+1}/{len(ordered)}] {method} {svc.url}{path}")
            result = self._call(svc, method, path, body, timeout)
            if result is not None:
                return result
            last_err = f"{svc.url} failed"

        raise Exception(f"All {len(ordered)} LLM services failed (last: {last_err})")

    def _call(
        self, svc: LLMService, method: str, path: str, body: Optional[bytes], timeout: int
    ) -> Optional[Tuple[int, dict, bytes]]:
        start = time.time()
        try:
            hdrs = {"Content-Type": "application/json"}
            if svc.api_key:
                hdrs["Authorization"] = f"Bearer {svc.api_key}"
            resp = requests.request(
                method=method, url=f"{svc.url}{path}",
                data=body, headers=hdrs, timeout=timeout,
            )
            elapsed = time.time() - start
            with self._lock:
                svc.total_requests += 1
                svc.last_response_time = elapsed
                svc.average_response_time = (
                    elapsed if svc.average_response_time == 0
                    else (svc.average_response_time * 0.9) + (elapsed * 0.1)
                )
            if resp.status_code < 500:
                with self._lock:
                    svc.successful_requests += 1
                    svc.consecutive_failures = 0
                    svc.healthy = True
                return (resp.status_code, dict(resp.headers), resp.content)
            # 5xx — count as failure
            with self._lock:
                svc.consecutive_failures += 1
                if svc.consecutive_failures >= self.max_consecutive_failures:
                    svc.healthy = False
            logger.warning(f"Service {svc.url} returned {resp.status_code}")
            return None

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout ({timeout}s) {svc.url}")
        except requests.exceptions.RequestException as exc:
            logger.warning(f"Request error {svc.url}: {exc}")
        except Exception as exc:
            logger.error(f"Unexpected error {svc.url}: {exc}")

        with self._lock:
            svc.consecutive_failures += 1
            if svc.consecutive_failures >= self.max_consecutive_failures:
                svc.healthy = False
        return None

    # ── Status ──────────────────────────────────────────────────────────

    def get_target(self) -> Tuple[Optional[str], Dict[str, str]]:
        """Return (url, headers) for the first service in routing order.
        Used by the streaming relay for /api/pull."""
        ordered = self._ordered_services()
        if not ordered:
            return None, {}
        svc = ordered[0]
        hdrs = {"Content-Type": "application/json"}
        if svc.api_key:
            hdrs["Authorization"] = f"Bearer {svc.api_key}"
        return svc.url, hdrs

    def get_service_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "load_balancing": self.load_balancing.value,
                "services": [
                    {
                        "index": i,
                        "url": svc.url,
                        "enabled": svc.enabled,
                        "healthy": svc.healthy,
                        "consecutive_failures": svc.consecutive_failures,
                        "total_requests": svc.total_requests,
                        "successful_requests": svc.successful_requests,
                        "success_rate": round(svc.success_rate, 2),
                        "average_response_time": round(svc.average_response_time, 3),
                        "health_score": round(svc.health_score, 2),
                    }
                    for i, svc in enumerate(self.services)
                ],
            }


# ── Singleton ───────────────────────────────────────────────────────────
LLM_Manager = LLMManager()
