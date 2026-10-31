#!/usr/bin/env python3
"""Fault-injecting HTTP proxy for the localnet (stdlib only).

All ports derive from PORT_BASE (env, default 22000, same offsets as scripts/localnet.env).
One listener per (role, backend): port = PORT_BASE+960 + role_idx*4 + backend_idx.
  backends: btc -> 127.0.0.1:PORT_BASE+2 (esplora)   goat -> +545 (anvil)
            graph -> +800 (graph-node)                proof -> +950 (mock proof builder)
Control API on 127.0.0.1:PORT_BASE+989 (JSON):
  GET  /health | /faults | /stats
  POST /fault  {"role": "all"|<role>, "backend": <b>, "type": <t>, "params": {...}, "ttl": secs}
  POST /clear  {"role"?: .., "backend"?: .., "type"?: ..}
Fault types (per key, stackable, every fault expires after ttl, default 600 s):
  latency   {ms, jitter}        delay before forwarding each request
  down      {}                  listener closed -> ECONNREFUSED
  blackhole {secs}              accept, read, never answer (close after secs if set)
  cut       {p}                 RST the connection mid-response with probability p
  http      {code, p}           answer <code> instead of forwarding, probability p
  slow      {ms_per_kb}         delay per KB of response body
  stall     {secs}              send the response head, then hang
  corrupt   {p}                 answer 200 with a non-JSON body
  flap      {on, off}           periodic down/up
Every forwarded request is sent with `Connection: close` (one request per client
connection), so request boundaries are unambiguous.
"""
import argparse
import asyncio
import json
import os
import random
import socket
import struct
import sys
import time

ROLES = ["committee_0", "committee_1", "operator_0", "verifier_0", "watchtower_0"]
PORT_BASE = int(os.environ.get("PORT_BASE", "22000"))
BACKENDS = [("btc", PORT_BASE + 2), ("goat", PORT_BASE + 545), ("graph", PORT_BASE + 800), ("proof", PORT_BASE + 950)]
BASE_PORT = PORT_BASE + 960
CTRL_PORT = PORT_BASE + 989
DEFAULT_TTL = 600
IDLE_SECS = 300
READ_LIMIT = 4 << 20


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)


def port_of(role, backend):
    return BASE_PORT + ROLES.index(role) * 4 + [b for b, _ in BACKENDS].index(backend)


class Proxy:
    def __init__(self):
        self.faults = {}      # key -> {type: {"params":..., "expires": t}}
        self.servers = {}     # key -> asyncio.Server | None
        self.flaps = {}       # key -> task
        self.stats = {}
        for r in ROLES:
            for b, _ in BACKENDS:
                self.stats[(r, b)] = {"requests": 0, "forwarded": 0, "errors": 0, "active": 0, "faulted": {}}

    # ---- fault bookkeeping -------------------------------------------------
    def active(self, key):
        now = time.time()
        f = self.faults.get(key, {})
        return {t: v["params"] for t, v in f.items() if v["expires"] > now}

    def faulted(self, key, t):
        d = self.stats[key]["faulted"]
        d[t] = d.get(t, 0) + 1

    async def set_fault(self, role, backend, ftype, params, ttl):
        keys = [(r, backend) for r in (ROLES if role == "all" else [role])]
        for key in keys:
            self.faults.setdefault(key, {})[ftype] = {"params": params, "expires": time.time() + ttl}
            if ftype == "down":
                await self.stop_listener(key)
            if ftype == "flap":
                self.cancel_flap(key)
                self.flaps[key] = asyncio.create_task(self.flap_loop(key, params))
            log(f"FAULT set {key[0]}/{key[1]} {ftype} {params} ttl={ttl}")

    async def clear(self, role=None, backend=None, ftype=None):
        n = 0
        for key in list(self.faults):
            if role and role != "all" and key[0] != role:
                continue
            if backend and key[1] != backend:
                continue
            for t in list(self.faults[key]):
                if ftype and t != ftype:
                    continue
                await self.drop_fault(key, t)
                n += 1
        return n

    async def drop_fault(self, key, t):
        self.faults.get(key, {}).pop(t, None)
        if t == "flap":
            self.cancel_flap(key)
        if t in ("down", "flap") and "down" not in self.faults.get(key, {}):
            await self.start_listener(key)
        log(f"FAULT cleared {key[0]}/{key[1]} {t}")

    def cancel_flap(self, key):
        task = self.flaps.pop(key, None)
        if task:
            task.cancel()

    async def flap_loop(self, key, params):
        on, off = float(params.get("on", 20)), float(params.get("off", 10))
        try:
            while True:
                await asyncio.sleep(on)
                await self.stop_listener(key)
                log(f"FLAP {key[0]}/{key[1]} down")
                await asyncio.sleep(off)
                if "down" not in self.faults.get(key, {}):
                    await self.start_listener(key)
                log(f"FLAP {key[0]}/{key[1]} up")
        except asyncio.CancelledError:
            pass

    async def sweeper(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()
            for key in list(self.faults):
                for t, v in list(self.faults[key].items()):
                    if v["expires"] <= now:
                        await self.drop_fault(key, t)
                        log(f"FAULT expired {key[0]}/{key[1]} {t}")

    # ---- listeners -----------------------------------------------------------
    async def start_listener(self, key):
        if self.servers.get(key):
            return
        role, backend = key
        upstream = dict(BACKENDS)[backend]
        srv = await asyncio.start_server(
            lambda r, w: self.handle(key, upstream, r, w), "127.0.0.1", port_of(role, backend), limit=READ_LIMIT
        )
        self.servers[key] = srv

    async def stop_listener(self, key):
        srv = self.servers.pop(key, None)
        if srv:
            srv.close()
            await srv.wait_closed()

    async def start_all(self):
        for key in self.stats:
            await self.start_listener(key)

    # ---- data path -------------------------------------------------------------
    async def handle(self, key, uport, reader, writer):
        st = self.stats[key]
        st["active"] += 1
        try:
            await self.handle_inner(key, uport, reader, writer, st)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            st["errors"] += 1
        except Exception as e:  # noqa: BLE001
            st["errors"] += 1
            log(f"ERROR {key[0]}/{key[1]}: {e!r}")
        finally:
            st["active"] -= 1
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def handle_inner(self, key, uport, reader, writer, st):
        f = self.active(key)
        if "blackhole" in f:
            self.faulted(key, "blackhole")
            secs = f["blackhole"].get("secs")
            try:
                await asyncio.wait_for(self.drain(reader), timeout=secs)
            except asyncio.TimeoutError:
                pass
            return
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=IDLE_SECS)
        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = await self.read_chunked(reader)
        else:
            body = await reader.readexactly(int(headers.get("content-length", "0") or 0))
        st["requests"] += 1
        f = self.active(key)
        if "latency" in f:
            ms = float(f["latency"].get("ms", 0))
            jit = float(f["latency"].get("jitter", 0))
            await asyncio.sleep(max(0.0, ms + random.uniform(-jit, jit)) / 1000)
        if "http" in f and random.random() < float(f["http"].get("p", 1)):
            code = int(f["http"].get("code", 503))
            self.faulted(key, "http")
            await self.reply(writer, code, b'{"error":"faultproxy injected"}')
            return
        if "corrupt" in f and random.random() < float(f["corrupt"].get("p", 1)):
            self.faulted(key, "corrupt")
            await self.reply(writer, 200, b"{\"result\": <<<not json>>>")
            return
        # forward with Connection: close
        out = [request_line]
        for ln in lines[1:]:
            if ln and not ln.lower().startswith(("connection:", "keep-alive:")):
                out.append(ln)
        out.append("Connection: close")
        new_head = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", uport), timeout=5)
        except (OSError, asyncio.TimeoutError):
            st["errors"] += 1
            await self.reply(writer, 502, b'{"error":"faultproxy: upstream unreachable"}')
            return
        try:
            uw.write(new_head + body)
            await uw.drain()
            resp_head = await ur.readuntil(b"\r\n\r\n")
            rl = resp_head.decode("latin-1").split("\r\n")
            rl = [ln for ln in rl if ln and not ln.lower().startswith(("connection:", "keep-alive:"))]
            rl.append("Connection: close")
            writer.write(("\r\n".join(rl) + "\r\n\r\n").encode("latin-1"))
            await writer.drain()
            if "stall" in f:
                self.faulted(key, "stall")
                await asyncio.sleep(float(f["stall"].get("secs", 3600)))
                return
            cut_p = float(f["cut"].get("p", 0)) if "cut" in f else 0.0
            slow = float(f["slow"].get("ms_per_kb", 0)) if "slow" in f else 0.0
            while True:
                chunk = await ur.read(65536)
                if not chunk:
                    break
                if cut_p and random.random() < cut_p:
                    self.faulted(key, "cut")
                    self.abort(writer)
                    return
                if slow:
                    await asyncio.sleep(slow * len(chunk) / 1024 / 1000)
                writer.write(chunk)
                await writer.drain()
            st["forwarded"] += 1
        finally:
            uw.close()

    @staticmethod
    async def drain(reader):
        while await reader.read(65536):
            pass

    @staticmethod
    async def read_chunked(reader):
        out = b""
        while True:
            line = await reader.readline()
            out += line
            size = int(line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while True:
                    t = await reader.readline()
                    out += t
                    if t in (b"\r\n", b""):
                        return out
            out += await reader.readexactly(size + 2)

    @staticmethod
    async def reply(writer, code, body):
        reason = {200: "OK", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
                  503: "Service Unavailable", 504: "Gateway Timeout"}.get(code, "Error")
        writer.write((f"HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        await writer.drain()

    @staticmethod
    def abort(writer):
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.close()

    # ---- control API --------------------------------------------------------
    async def control(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            lines = head.decode().split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            clen = 0
            for ln in lines[1:]:
                if ln.lower().startswith("content-length:"):
                    clen = int(ln.split(":", 1)[1])
            body = await reader.readexactly(clen) if clen else b""
            req = json.loads(body) if body else {}
            code, resp = 200, {}
            if path == "/health":
                resp = {"ok": True, "listeners": len([s for s in self.servers.values() if s])}
            elif path == "/faults":
                now = time.time()
                resp = {f"{k[0]}/{k[1]}": {t: {"params": v["params"], "ttl_left": round(v["expires"] - now)}
                                            for t, v in fs.items() if v["expires"] > now}
                        for k, fs in self.faults.items()}
                resp = {k: v for k, v in resp.items() if v}
            elif path == "/stats":
                resp = {f"{k[0]}/{k[1]}": v for k, v in self.stats.items()}
            elif path == "/fault" and method == "POST":
                role, backend, ftype = req.get("role", "all"), req["backend"], req["type"]
                if role != "all" and role not in ROLES or backend not in dict(BACKENDS):
                    code, resp = 400, {"error": "unknown role/backend"}
                else:
                    await self.set_fault(role, backend, ftype, req.get("params", {}), float(req.get("ttl", DEFAULT_TTL)))
                    resp = {"ok": True}
            elif path == "/clear" and method == "POST":
                resp = {"cleared": await self.clear(req.get("role"), req.get("backend"), req.get("type"))}
            else:
                code, resp = 404, {"error": "no such route"}
            await self.reply(writer, code, json.dumps(resp).encode())
        except Exception as e:  # noqa: BLE001
            try:
                await self.reply(writer, 500, json.dumps({"error": repr(e)}).encode())
            except Exception:  # noqa: BLE001
                pass
        finally:
            writer.close()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctrl-port", type=int, default=CTRL_PORT)
    args = ap.parse_args()
    p = Proxy()
    await p.start_all()
    ctrl = await asyncio.start_server(p.control, "127.0.0.1", args.ctrl_port)
    asyncio.create_task(p.sweeper())
    log(f"faultproxy up: {len(p.servers)} listeners on {BASE_PORT}-{BASE_PORT + len(p.servers) - 1}, control {args.ctrl_port}")
    async with ctrl:
        await ctrl.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
