"""Rate-limit presence probe.

EXTRACTED CAPABILITY (CAP-025).

This module answers one question -- does throttling exist? -- and is built so
that it cannot answer it by causing harm. The shape is taken from the source,
where the discipline was deliberate and documented:

  * a FIXED request count and worker ceiling, never a ramp or a sustained load
  * every request carries a FRESH identifier so each is refused at the business
    layer and no state changes
  * hard ceilings enforced in code, not left to a caller's judgement
  * the result records whether the throughput figure is CITABLE: a proxied run
    understates the achievable rate because of proxy latency, so only a direct
    measurement may be quoted in a report

It is classed volumetric, so the default scope policy denies it until an
engagement records an authorisation.
"""
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from ..corpus.payload import PayloadTemplate
from ..corpus.payload import get as pget
from ..core.errors import ScopeViolation

#: Absolute ceilings. A caller cannot exceed these, whatever it asks for.
MAX_REQUESTS = 200
MAX_WORKERS = 16

THROTTLE_STATUSES = ("429", "503")


class RateResult(object):
    def __init__(self, requests, workers, elapsed, statuses, latencies,
                 via, citable, retry_after_seen, endpoint):
        self.requests = requests
        self.workers = workers
        self.elapsed = elapsed
        self.statuses = dict(statuses)
        self.latencies = list(latencies)
        self.via = via
        self.citable = citable
        self.retry_after_seen = retry_after_seen
        self.endpoint = endpoint

    @property
    def rps(self):
        return (self.requests / self.elapsed) if self.elapsed else 0.0

    @property
    def throttled(self):
        return sum(self.statuses.get(s, 0) for s in THROTTLE_STATUSES)

    def verdict(self):
        if self.throttled:
            return ("THROTTLING OBSERVED",
                    "%d of %d request(s) were throttled (%s)%s"
                    % (self.throttled, self.requests,
                       ", ".join("%s x%d" % (s, self.statuses[s])
                                 for s in THROTTLE_STATUSES
                                 if s in self.statuses),
                       "; Retry-After present" if self.retry_after_seen
                       else "; no Retry-After header"))
        return ("NO THROTTLING OBSERVED",
                "no %s responses at %.1f req/s over %.2f s"
                % ("/".join(THROTTLE_STATUSES), self.rps, self.elapsed))

    def as_dict(self):
        lat = self.latencies or [0.0]
        verdict, detail = self.verdict()
        return {
            "module": "rate_limit",
            "endpoint": self.endpoint,
            "requests": self.requests,
            "workers": self.workers,
            "elapsed_s": round(self.elapsed, 3),
            "throughput_rps": round(self.rps, 2),
            "statuses": self.statuses,
            "throttled_responses": self.throttled,
            "retry_after_seen": self.retry_after_seen,
            "latency_min_s": round(min(lat), 3),
            "latency_avg_s": round(sum(lat) / len(lat), 3),
            "latency_max_s": round(max(lat), 3),
            "via": self.via,
            "throughput_citable": self.citable,
            "citability_note": (
                "measured directly; this figure may be quoted"
                if self.citable else
                "measured THROUGH A PROXY: proxy latency understates the "
                "achievable rate, so this throughput figure must NOT be quoted "
                "as the target's capacity. Re-measure directly to cite a rate."),
            "verdict": verdict,
            "verdict_detail": detail,
            "safety_note": (
                "Bounded probe: fixed count, capped concurrency, fresh "
                "identifier per request so each is refused at the business "
                "layer and no state is changed. Not a load or denial-of-service "
                "test."),
        }


def probe(profile, auth_provider, transport, endpoint_id=None, requests=80,
          workers=8, scope_policy=None, authorised=False):
    """Run a bounded burst. Returns a RateResult.

    *authorised* must be True, or the probe refuses to run. The flag exists so
    that reaching this function by accident cannot generate volume: the scope
    policy is the primary gate, and this is the backstop.
    """
    if not authorised:
        raise ScopeViolation(
            "the rate-limit probe generates request volume and is classed "
            "volumetric; it runs only with authorised=True, which requires an "
            "authorisation recorded in the engagement scope policy")
    if requests > MAX_REQUESTS or workers > MAX_WORKERS:
        raise ScopeViolation(
            "requested %d requests / %d workers exceeds the module ceiling of "
            "%d / %d; these limits are deliberate and are not configurable"
            % (requests, workers, MAX_REQUESTS, MAX_WORKERS))

    endpoint_id = endpoint_id or profile.endpoint_ids[0]
    url = profile.url_for(endpoint_id)
    tpl = PayloadTemplate(profile.template_for(endpoint_id), endpoint_id)
    ep = profile.endpoint(endpoint_id)
    spaces = profile.data.get("identifier_spaces") or {}

    def one(i):
        ident = (profile.identifier_for(endpoint_id)
                 if ep.get("identifier_space") else None)
        corr = (profile.generate_identifier("correlation")
                if (tpl.correlation_path and "correlation" in spaces)
                else (pget(tpl.body, tpl.correlation_path)
                      if tpl.correlation_path else None))
        body = tpl.dumps(tpl.instantiate(identifier=ident, correlation=corr))
        t0 = time.time()
        resp = transport.send("rate-%03d" % i, url, method="POST", body=body)
        return resp.status, time.time() - t0, resp.header("Retry-After")

    start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, range(requests)))
    elapsed = time.time() - start

    statuses = Counter(r[0] for r in results)
    latencies = [r[1] for r in results]
    retry_after = any(r[2] for r in results)
    via = transport.profile.proxy if transport.via_proxy else "direct"
    citable = not transport.via_proxy

    return RateResult(requests, workers, elapsed, statuses, latencies, via,
                      citable, retry_after, endpoint_id)
