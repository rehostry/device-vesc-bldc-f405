#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live web panel for the vesc-bldc-f405 re-host + its attack.

One browser tab that boots the real rehosted VESC firmware, speaks its own COMM
protocol to it, and shows -- live -- the firmware's replies and the attack's
before/after evidence.

Transport is plain ``/state`` POLLING (no Server-Sent Events): SSE is buffered by
tunnelling proxies, so an EventSource panel is a permanently blank page remotely
while it works on localhost (playbook §2.5). The page GETs ``/state`` every 1.5 s
and POSTs /boot /refresh /attack /stop.

    rehostry-vesc-bldc-f405-panel     # http://127.0.0.1:9011
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attack, spawn

_LOCK = threading.Lock()
_STATE = {"busy": False, "ready": False, "stage": "idle", "log": [],
          "state": None, "attack": None}
_SC = {"scenario": None}
ARGS: argparse.Namespace


def _on_stage(name, **data):
    with _LOCK:
        _STATE["stage"] = name
        if data.get("note"):
            _STATE["log"].append({"stage": name, "note": data["note"]})
            _STATE["log"] = _STATE["log"][-60:]
        if "state" in data:
            _STATE["state"] = data["state"]
        if "result" in data:
            _STATE["attack"] = data["result"]


def _boot():
    sc = attack.VescScenario(bridge_port=ARGS.port, log_dir=ARGS.log_dir)
    _SC["scenario"] = sc
    try:
        with _LOCK:
            _STATE.update(busy=True, ready=False, stage="booting", log=[],
                          state=None, attack=None)
        if not sc.boot(_on_stage):
            return
        _on_stage("read", state=sc.read_state())
        with _LOCK:
            _STATE["ready"] = True
        _on_stage("ready", note="firmware live -- read the state or run the attack")
    except Exception as exc:  # noqa: BLE001
        _on_stage("error", note="error: %s" % exc)
    finally:
        with _LOCK:
            _STATE["busy"] = False


def _refresh():
    sc = _SC["scenario"]
    if sc:
        _on_stage("read", state=sc.read_state())


def _attack():
    sc = _SC["scenario"]
    if sc:
        _on_stage("attack", result=sc.attack())
        _on_stage("read", state=sc.read_state())


def _shutdown_scenario():
    sc = _SC["scenario"]
    if sc:
        sc.shutdown()
        _SC["scenario"] = None
    with _LOCK:
        _STATE.update(ready=False, stage="stopped")
    _on_stage("stopped", note="firmware stopped")


PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VESC 100/250 &mdash; rehosted motor controller</title>
<style>
 body{background:#0a0a0a;color:#cdd;font:14px/1.5 -apple-system,Menlo,monospace;margin:0;padding:16px}
 .wrap{max-width:860px;margin:0 auto}
 .card{background:#141414;border:1px solid #262626;border-radius:8px;padding:14px;margin:12px 0}
 button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:9px 14px;font-size:13px;cursor:pointer;margin:0 6px 6px 0}
 button.atk{background:#a4331f} button:disabled{opacity:.4;cursor:default}
 .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;margin-left:8px}
 .pill.on{background:#132e1a;color:#3fb950} .pill.off{background:#2d1618;color:#f85149}
 pre{background:#000;border-radius:8px;padding:10px;overflow:auto;color:#8b949e}
 .log{font-size:12px;background:#000;border-radius:8px;padding:10px;max-height:150px;overflow:auto;color:#8b949e}
 .log b{color:#58a6ff}
 details.brief{background:#101820;border-color:#1f3350}
 details.brief summary{cursor:pointer;color:#cdd;font-size:13px}
 details.brief .body{margin-top:8px}
 details.brief p{margin:6px 0;color:#9db3c8;font-size:13px}
 details.brief b{color:#cdd}
</style></head><body><div class=wrap>
<h1>VESC 100/250 &mdash; rehosted BLDC/FOC motor controller</h1>
<details class="card brief" open>
 <summary><b>About this panel</b> &mdash; what it is, what to do, what to expect</summary>
 <div class=body>
  <p><b>Device.</b> A <b>VESC 100/250</b> brushless motor controller (the open-source
     ESC used on electric skateboards, e-bikes, robots and small EVs) running the
     project's own firmware &mdash; vedderb/bldc 7.01, ChibiOS on an STM32F405 &mdash;
     built from source and emulated instruction by instruction. In the field it
     drives a motor at up to 100&nbsp;V / 250&nbsp;A and is configured over a
     3-pin UART header, CAN, or USB.</p>
  <p><b>Steps.</b> 1) <b>Boot firmware</b> &mdash; takes about a minute while
     ChibiOS starts, the emulated EEPROM is read and the motor-control layer comes
     up &rarr; 2) <b>Re-read</b> pulls the live configuration back out of the
     device &rarr; 3) <b>Run attack</b> &rarr; 4) <b>Stop</b>.</p>
  <p><b>What you're seeing.</b> The <b>STATE</b> card is decoded from the
     firmware's own COMM replies over USART3 &mdash; the firmware version, the
     hardware name and serial it reports, and its live motor-current limits. It is
     not host bookkeeping: every number there was framed and CRC-checked by the
     firmware's own <code>packet.c</code>. The log shows boot and attack stages.</p>
  <p><b>The attack.</b> The red button sends one unauthenticated
     <code>COMM_SET_MCCONF</code> packet that raises <b>l_current_max</b>, the
     motor-current limit, to <b>271&nbsp;A</b>. VESC's protocol has no
     authentication, no session and no sequence number; the only thing guarding
     the write is a fixed four-byte "signature" that is a firmware-version tag,
     identical on every VESC of this version, and which the device hands out
     itself in every read. Anyone who can reach the UART header, the CAN bus or
     the USB port can therefore remove the motor's overcurrent protection &mdash;
     and the new limit is written to the controller's EEPROM, so it survives a
     power cycle.</p>
  <p><b>Expect.</b> Success is <b>l_current_max</b> in the STATE card changing to
     271&nbsp;A, read back by a second, independent request after the write. The
     panel also runs two controls the firmware must fail: the same write with a
     corrupted signature (the device answers with its own
     "Could not set mcconf due to wrong signature" and the value does <i>not</i>
     change) and a frame with a bad CRC (dropped silently, no reply). A device
     that authenticated its configuration writes &mdash; or a harness that was
     only measuring itself &mdash; would show the limit unchanged, and the verdict
     would read <code>"landed": false</code>.</p>
 </div>
</details>
<div class=card>
 <button id=boot onclick="post('/boot')">&#9889; Boot firmware</button>
 <button id=refresh onclick="post('/refresh')" disabled>&#8635; Re-read</button>
 <button id=stop onclick="post('/stop')" disabled>&#9632; Stop</button>
 <span id=state class=pill></span>
</div>
<div class=card><b>STATE</b> &mdash; decoded from the firmware's own COMM replies<pre id=st>&mdash; boot to populate &mdash;</pre></div>
<div class=card>
 <button id=atk class=atk onclick="post('/attack')" disabled>&#9760; Run attack &mdash; raise the current limit to 271 A</button>
 <pre id=atkbox></pre>
</div>
<div class=card><div class=log id=log>ready. click to boot the firmware.</div></div>
</div>
<script>
function render(s){
  document.getElementById('boot').disabled=s.busy||s.ready;
  document.getElementById('refresh').disabled=!s.ready||s.busy;
  document.getElementById('stop').disabled=!s.ready&&!s.busy;
  document.getElementById('atk').disabled=!s.ready||s.busy;
  const sp=document.getElementById('state');
  sp.className='pill '+(s.ready?'on':'off'); sp.textContent=s.ready?'firmware live':(s.busy?'booting':'offline');
  document.getElementById('st').textContent=s.state?JSON.stringify(s.state,null,2):'— boot to populate —';
  document.getElementById('atkbox').textContent=s.attack?JSON.stringify(s.attack,null,2):'';
  const log=document.getElementById('log');
  log.innerHTML=(s.log||[]).map(l=>'<b>'+l.stage+'</b> '+(l.note||'')).join('<br>')||'ready.';
  log.scrollTop=log.scrollHeight;
}
function post(p){fetch(p,{method:'POST'}).then(()=>setTimeout(poll,300));}
function poll(){fetch('/state').then(r=>r.json()).then(render).catch(()=>{});}
poll(); setInterval(poll, 1500);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: ARG002 - quiet
        pass

    def _send(self, code, ctype, body):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/state":
            with _LOCK:
                body = json.dumps(_STATE)
            self._send(200, "application/json", body)
            return
        if path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE)
            return
        self._send(404, "text/plain", b"not found")

    def do_POST(self):  # noqa: N802
        with _LOCK:
            busy = _STATE["busy"]
            ready = _STATE["ready"]
        if self.path.startswith("/boot"):
            if not busy and not ready:
                threading.Thread(target=_boot, daemon=True).start()
        elif self.path.startswith("/refresh"):
            if ready and not busy:
                threading.Thread(target=_refresh, daemon=True).start()
        elif self.path.startswith("/attack"):
            if ready and not busy:
                threading.Thread(target=_attack, daemon=True).start()
        elif self.path.startswith("/stop"):
            threading.Thread(target=_shutdown_scenario, daemon=True).start()
        else:
            self._send(404, "text/plain", b"not found")
            return
        self._send(200, "application/json", b'{"ok":true}')


def main(argv=None) -> int:
    global ARGS
    p = argparse.ArgumentParser(
        description="Live web panel for the rehosted VESC 100/250 + its attack")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("VESC_HTTP_PORT", "9011")),
                   help="panel HTTP port (default from VESC_HTTP_PORT, else 9011)")
    p.add_argument("--bridge-port", type=int, default=spawn.BRIDGE_PORT,
                   dest="port_bridge",
                   help="the USART3 <-> COMM bridge TCP port (default %d)"
                        % spawn.BRIDGE_PORT)
    p.add_argument("--log-dir", default="/tmp", help="where to write the emulator boot log")
    p.add_argument("--no-open", action="store_true", help="don't open a browser")
    args = p.parse_args(argv)
    ARGS = argparse.Namespace(http_port=args.port, port=args.port_bridge,
                              log_dir=args.log_dir, no_open=args.no_open)

    httpd = ThreadingHTTPServer(("127.0.0.1", ARGS.http_port), Handler)
    httpd.daemon_threads = True
    url = "http://127.0.0.1:%d" % ARGS.http_port
    print("[vesc_panel] polling panel on %s (VESC COMM seam on tcp/%d)"
          % (url, ARGS.port))
    if not ARGS.no_open:
        threading.Thread(target=lambda: (time.sleep(0.6), webbrowser.open(url)),
                         daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        _shutdown_scenario()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
