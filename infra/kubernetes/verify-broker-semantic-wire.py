#!/usr/bin/env python3
"""Live SPIRE -> Envoy -> broker-state semantic-wire conformance gate."""
from __future__ import annotations
import hashlib, json, os, platform, subprocess, tempfile, time, uuid
from pathlib import Path
from andyur.dataplane.brokertransport import (BrokerIngressTransport, BrokerTransport,
    build_egress_bootstrap, build_ingress_bootstrap)

ROOT=Path(__file__).resolve().parents[2]; SPIRE=ROOT/"infra/spire/docker/verify-slice3.sh"
ENVOY=("docker.io/envoyproxy/envoy@sha256:"
 "d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66")
IMAGE=os.environ.get("ANDYUR_BROKER_WIRE_SERVER_IMAGE","").strip()
NET="andyur-spire-net"; SVOL="andyur-spire-sockets"; TD="andyur.local"
NAMES=("andyur-wire-backend","andyur-wire-ingress","andyur-wire-egress",
       "andyur-wire-egress-wrong","andyur-wire-client")
SOURCES={"andyur/dataplane/brokertransport.py","andyur/server/brokerstate_server.py",
 "andyur/server/auth.py","andyur/server/app.py",
 "infra/kubernetes/verify-broker-semantic-wire.py",
 "infra/kubernetes/verify-broker-semantic-wire.sh","infra/spire/docker/agent.conf",
 "infra/spire/docker/server.conf"}
RESULT=ROOT/"infra/kubernetes/result-broker-semantic-wire-2026-08-20-macos-arm64.json"

def run(*a, check=True, timeout=60, input_text=None):
    r=subprocess.run(a,text=True,input=input_text,capture_output=True,timeout=timeout)
    if check and r.returncode: raise RuntimeError(f"failed: {' '.join(a)}\n{r.stdout}\n{r.stderr}")
    return r
def docker(*a,**kw): return run("docker",*a,**kw)
def clean():
    docker("rm","-f",*NAMES,check=False)
def entry(sid,*sels):
    a=["exec","andyur-spire-server","/opt/spire/bin/spire-server","entry","create",
       "-parentID",f"spiffe://{TD}/agent/node","-spiffeID",sid,
       "-x509SVIDTTL","45","-jwtSVIDTTL","300"]
    for s in sels:a+=["-selector",s]
    docker(*a)
def py(name,code,*,label=None,vols=(),env=None,network=NET,timeout=30):
    a=["run","--rm","--name",name,"--network",network]
    for item in ((label,) if isinstance(label,str) else (label or ())):
        a+=["--label",item]
    for v in vols:a+=["-v",v]
    for k,v in (env or {}).items():a+=["-e",f"{k}={v}"]
    return docker(*a,"--entrypoint","python",IMAGE,"-c",code,timeout=timeout)
def call(vol,rid,token,label,jwt="",forged=False):
    code="""import json,os,httpx
from andyur import identity
h={'X-Andyur-Run-Token':os.environ['T']}
h.update({'Authorization':'Bearer '+os.environ['J']} if os.environ.get('J') else identity.auth_header())
if os.environ.get('F'):h['X-Forwarded-Client-Cert']=os.environ['F']
with httpx.Client(transport=httpx.HTTPTransport(uds='/run/egress/state.sock'),timeout=5,trust_env=False) as c:
 r=c.get('http://andyur-broker-state'+os.environ['P'],headers=h)
print(json.dumps({'status':r.status_code,'body':r.text,'jwt':h['Authorization'][7:]}))"""
    r=py("andyur-wire-client",code,label=label,
      vols=(f"{SVOL}:/run/spire/sockets:ro",f"{vol}:/run/egress"),
      env={"SPIFFE_ENDPOINT_SOCKET":"unix:/run/spire/sockets/api.sock",
       "T":token,"J":jwt,
       "F":(forged if isinstance(forged,str) else
            ("URI=spiffe://attacker.invalid/agent/x/run/"+"f"*32 if forged else "")),
       "P":f"/runs/{rid}/broker-state"})
    return json.loads(r.stdout.strip().splitlines()[-1])
def admin(container,path):
    code=("import urllib.request;print(urllib.request.urlopen("
          f"'http://127.0.0.1:9902{path}',timeout=5).read().decode())")
    return json.loads(py("andyur-wire-client",code,network=f"container:{container}").stdout)
def serials(container):
    return sorted(str(c["serial_number"]) for x in admin(container,"/certs?format=json").get("certificates",[])
                  for c in x.get("cert_chain",[]) if c.get("serial_number"))

def wait_entry(label,sid,seconds=60):
    """Block until a container carrying `label` can actually fetch its SVID.

    The probe asks for the very thing the gate is about to rely on, so what is
    waited for is what is asserted rather than a proxy for it.
    """
    code=("import sys\n"
          "from andyur import identity\n"
          "try: identity.fetch_token(); sys.exit(0)\n"
          "except Exception: sys.exit(1)")
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            py("andyur-wire-entry",code,label=label,
               vols=(f"{SVOL}:/run/spire/sockets:ro",),
               env={"SPIFFE_ENDPOINT_SOCKET":"unix:/run/spire/sockets/api.sock",
                    "ANDYUR_SVID_TIMEOUT":"5"},timeout=15)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"entry {sid} never propagated to the agent within {seconds}s")


def main():
    if not IMAGE: raise SystemExit("ANDYUR_BROKER_WIRE_SERVER_IMAGE must name a fresh current-source image")
    image_id=docker("image","inspect",IMAGE,"--format","{{.Id}}").stdout.strip()
    image_sources=sorted(p for p in SOURCES if p.startswith("andyur/"))
    attest_code=("import hashlib,json,pathlib;"
      "print(json.dumps({p:hashlib.sha256(pathlib.Path('/app',p).read_bytes()).hexdigest()"
      " for p in "+repr(image_sources)+"}))")
    executed=json.loads(py("andyur-wire-client",attest_code,network="none").stdout)
    host_executed={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
                   for p in image_sources}
    if not executed or executed != host_executed:
        raise RuntimeError("running server image source does not match host source")
    started=time.time(); rid=uuid.uuid4().hex; wrong=uuid.uuid4().hex; agent="wire-agent"
    rs=f"spiffe://{TD}/agent/{agent}/run/{rid}"; ws=f"spiffe://{TD}/agent/{agent}/run/{wrong}"
    cs=f"spiffe://{TD}/control-plane"; bv=f"andyur-wire-b-{rid[:8]}"
    ev=f"andyur-wire-e-{rid[:8]}"; wv=f"andyur-wire-w-{rid[:8]}"; vols=(bv,ev,wv)
    result={}; clean()
    for v in vols:
     docker("volume","create",v)
     docker("run","--rm","-v",f"{v}:/volume","--entrypoint","python",IMAGE,
            "-c","import os;os.chown('/volume',0,1000);os.chmod('/volume',0o2770)")
    try:
      run("bash",str(SPIRE),"up",timeout=90)
      entry(cs,"docker:label:andyur.role:wire-control")
      entry(rs,f"docker:label:andyur.run_id:{rid}",f"docker:label:andyur.agent:{agent}")
      entry(ws,"docker:label:andyur.role:wire-wrong")
      # WAIT UNTIL EVERY ENTRY RESOLVES, bounded, rather than sleeping 6s.
      # Registration is synchronous; propagation is not. The wrong entry guards a
      # SECURITY negative control -- the wrong-peer leg must be refused for the
      # right reason, and an entry that had not yet propagated produces a
      # refusal too, which is indistinguishable from the property under test.
      wait_entry("andyur.role=wire-control", cs)
      wait_entry((f"andyur.run_id={rid}",f"andyur.agent={agent}"), rs)
      wait_entry("andyur.role=wire-wrong", ws)
      def profile(sid,vol):
        return BrokerTransport(sid,cs,TD,"/run/egress/state.sock","andyur-wire-ingress",
          9443,"/run/backend/socket/state.sock","/run/spire/sockets/api.sock")
      good=profile(rs,ev); bad=profile(ws,wv)
      ing=BrokerIngressTransport(cs,TD,9443,"/run/backend/socket/state.sock","/run/spire/sockets/api.sock")
      with tempfile.TemporaryDirectory(prefix="andyur-wire-") as d:
       d=Path(d); configs={"egress.json":build_egress_bootstrap(good),
         "wrong.json":build_egress_bootstrap(bad),"ingress.json":build_ingress_bootstrap(ing)}
       # A CHANGED CONFIG GETS A NEW FILENAME, and its container is recreated
       # rather than restarted.
       #
       # Rewriting a config in place and restarting Envoy delivered a TRUNCATED
       # file: "Unable to parse JSON as proto (INVALID_ARGUMENT: unexpected
       # EOF)". The mutation below makes wrong.json 27 bytes LONGER (2989 ->
       # 3016), and the container kept seeing exactly the original length --
       # the host directory crosses a VM filesystem share, and the guest's view
       # of that path was capped at the size it had when the container first
       # read it. Writing to a temp file and renaming did not help, because the
       # stale view follows the PATH. The identical bytes validate clean under
       # `envoy --mode validate` at a path no container has read before, which
       # is how we know the config was never the problem.
       #
       # This is worth knowing beyond this gate: any harness that rewrites a
       # bind-mounted file and expects a container to see the new content has
       # the same defect, and it only shows up when the file grows.
       generation={}
       def write_config(name):
        generation[name]=generation.get(name,0)+1
        stem,_,ext=name.rpartition(".")
        path=f"{stem}-{generation[name]}.{ext}"
        (d/path).write_text(json.dumps(configs[name],sort_keys=True))
        return path
       live={n:write_config(n) for n in configs}
       result["config_sha256"]={n:hashlib.sha256((d/live[n]).read_bytes()).hexdigest()
                                for n in configs}
       env={"SPIFFE_ENDPOINT_SOCKET":"unix:/run/spire/sockets/api.sock",
        "ANDYUR_AGENT_AUTH":"on","ANDYUR_REQUIRE_RUN_SVID":"on",
        "ANDYUR_RUN_TOKEN_SECRET":"semantic-wire-secret","ANDYUR_DATA_DIR":"/run/backend/data",
        "ANDYUR_BROKER_STATE_SOCKET":"/run/backend/socket/state.sock",
        "ANDYUR_BROKER_STATE_GID":"1000","ANDYUR_BROKER_PROVISION_PARENT":"on"}
       a=["run","-d","--name","andyur-wire-backend","--network",NET,
          "--label","andyur.role=wire-control","-v",f"{SVOL}:/run/spire/sockets:ro",
          "-v",f"{bv}:/run/backend"]
       for k,v in env.items():a+=["-e",f"{k}={v}"]
       docker(*a,"--entrypoint","python",IMAGE,"-m","andyur.server.brokerstate_server")
       for _ in range(40):
        q=docker("exec","andyur-wire-backend","python","-m","andyur.server.brokerstate_server","--check",check=False)
        if q.returncode==0:break
        time.sleep(1)
       else:
        logs=docker("logs","andyur-wire-backend",check=False)
        raise RuntimeError("backend not ready: "+(logs.stdout+logs.stderr)[-4000:])
       seed=f"""from andyur import db
from andyur.server import runtoken
db.init_db()
with db.connect() as c:
 c.execute("INSERT INTO agents (name,created_at) VALUES (?,?)",("wire-agent",db.utcnow()))
 c.execute("INSERT INTO runs (id,agent,state,created_at,workflow_id,acting_user,scope,subject_context,registry_digest,ceiling_audiences) VALUES (?,?,'running',?,'wf','alice',?,?,?,?)",({rid!r},"wire-agent",db.utcnow(),'["read"]','{{"account":"447"}}',"sha256:"+"a"*64,'["urn:calendar"]'))
print(runtoken.mint("wire-agent",{rid!r},"wf",purpose=runtoken.PURPOSE_BROKER))"""
       token=docker("exec","-i","andyur-wire-backend","python","-",input_text=seed).stdout.strip().splitlines()[-1]
       common=["--network",NET,"--user","1337:1337","--group-add","1000",
               "-v",f"{SVOL}:/run/spire/sockets:ro"]
       docker("run","-d","--name","andyur-wire-ingress",*common,"--network-alias","andyur-wire-ingress",
        "--label","andyur.role=wire-control","-v",f"{bv}:/run/backend","-v",f"{d}:/cfg:ro",
        ENVOY,"envoy","-c",f"/cfg/{live['ingress.json']}")
       for name,sid,lab,vol,cfg in (("andyur-wire-egress",rs,f"andyur.run_id={rid}",ev,"egress.json"),
         ("andyur-wire-egress-wrong",ws,"andyur.role=wire-wrong",wv,"wrong.json")):
        labels=["--label",lab]
        if name=="andyur-wire-egress":labels+=["--label",f"andyur.agent={agent}"]
        docker("run","-d","--name",name,*common,*labels,"-v",f"{vol}:/run/egress",
         "-v",f"{d}:/cfg:ro",ENVOY,"envoy","-c",f"/cfg/{live[cfg]}")
       def recreate(name,lab,vol,cfg,extra=()):
        """Replace an Envoy so it reads the CURRENT config, at a fresh path."""
        docker("rm","-f",name,check=False)
        docker("run","-d","--name",name,*common,"--label",lab,*extra,
         *(("--network-alias",name) if name=="andyur-wire-ingress" else ()),
         "-v",f"{vol}:{'/run/backend' if name=='andyur-wire-ingress' else '/run/egress'}",
         "-v",f"{d}:/cfg:ro",ENVOY,"envoy","-c",f"/cfg/{live[cfg]}")
       # WAIT for the egress Envoy's UDS to accept a connection, bounded, rather
       # than a fixed 7s sleep that raced Envoy startup under load (connection
       # refused). A ConnectError is not-yet-listening (retry); ANY HTTP response
       # means the listener is up. This is a readiness wait, not a retried
       # assertion -- the semantic calls below still run exactly once.
       # exit 0 ONLY on an HTTP response (listener up); exit 1 on ANY failure --
       # a missing UDS raises OSError/FileNotFoundError, not just ConnectError,
       # so a blanket "any exception -> not ready" is what keeps this honest.
       ready=("import httpx,sys\n"
              "try:\n"
              " with httpx.Client(transport=httpx.HTTPTransport("
              "uds='/run/egress/state.sock'),timeout=2,trust_env=False) as c:\n"
              "  c.get('http://x/')\n"
              " sys.exit(0)\n"
              "except Exception: sys.exit(1)")
       # BOTH egress Envoys, and after every restart. The wait existed for one
       # of the two and the OTHER was assumed instantly up, so the wrong-peer
       # leg failed with "connection refused" on a loaded host and passed on an
       # idle one -- the gate's verdict depended on the machine that ran it,
       # which is the one thing a gate may not do. Same for the two restarts
       # below, which slept a fixed 5s.
       def wait_ready(vol, who, container=None):
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
         try:
          py("andyur-wire-ready",ready,vols=(f"{vol}:/run/egress",),timeout=10)
          return
         except Exception:
          time.sleep(1)
        # SAY WHY. A readiness timeout that reports only "never became
        # reachable" cannot distinguish a slow start from an Envoy that
        # rejected its config and exited -- and the mutation step deliberately
        # writes a config Envoy may refuse, so those two are exactly the cases
        # that have to be told apart.
        detail=""
        if container:
         st=docker("inspect","--format","{{.State.Status}} exit={{.State.ExitCode}}",
                   container,check=False).stdout.strip()
         logs=docker("logs","--tail","25",container,check=False)
         detail=f"\n  state: {st}\n  logs:\n{logs.stdout}{logs.stderr}"
        raise RuntimeError(
            f"{who} Envoy UDS never became reachable within 60s{detail}")
       wait_ready(ev,"egress","andyur-wire-egress")
       wait_ready(wv,"wrong-peer egress","andyur-wire-egress-wrong")
       run_labels=(f"andyur.run_id={rid}",f"andyur.agent={agent}")
       pos=call(ev,rid,token,run_labels,forged=True)
       if pos["status"]!=200:raise RuntimeError(f"positive failed: {pos}")
       state=json.loads(pos["body"]); jwt=pos["jwt"]
       replay=call(wv,rid,token,"andyur.role=wire-wrong",jwt=jwt)
       if replay["status"]!=403:raise RuntimeError(f"wrong-peer replay not refused: {replay}")
       # Mutate both enforcement points that keep caller text from becoming
       # identity. The stolen credentials must succeed only while the exact
       # sanitizer/SAN-derived-XFCC defect is live, then fail after restoration.
       whcm=configs["wrong.json"]["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
       ihcm=configs["ingress.json"]["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
       whcm["route_config"]["virtual_hosts"][0]["routes"][0]["request_headers_to_remove"].remove(
           "x-forwarded-client-cert")
       whcm["forward_client_cert_details"]="ALWAYS_FORWARD_ONLY"
       ihcm["forward_client_cert_details"]="FORWARD_ONLY"
       for n in ("wrong.json","ingress.json"): live[n]=write_config(n)
       recreate("andyur-wire-ingress","andyur.role=wire-control",bv,"ingress.json")
       recreate("andyur-wire-egress-wrong","andyur.role=wire-wrong",wv,"wrong.json")
       wait_ready(wv,"wrong-peer egress after mutation","andyur-wire-egress-wrong")
       forged_peer=f"URI={rs}"
       mutation=call(wv,rid,token,"andyur.role=wire-wrong",jwt=jwt,forged=forged_peer)
       if mutation["status"]!=200:raise RuntimeError(f"identity mutation did not turn red: {mutation}")
       configs["wrong.json"]=build_egress_bootstrap(bad)
       configs["ingress.json"]=build_ingress_bootstrap(ing)
       for n in ("wrong.json","ingress.json"): live[n]=write_config(n)
       recreate("andyur-wire-ingress","andyur.role=wire-control",bv,"ingress.json")
       recreate("andyur-wire-egress-wrong","andyur.role=wire-wrong",wv,"wrong.json")
       wait_ready(wv,"wrong-peer egress after restoration","andyur-wire-egress-wrong")
       restored=call(wv,rid,token,"andyur.role=wire-wrong",jwt=jwt,forged=forged_peer)
       if restored["status"]!=403:raise RuntimeError(f"identity restoration did not close replay: {restored}")
       before=serials("andyur-wire-ingress"); deadline=time.monotonic()+60; after=before
       while after==before and time.monotonic()<deadline:time.sleep(4); after=serials("andyur-wire-ingress")
       if not before or after==before:raise RuntimeError("Envoy SDS certificate did not rotate")
       saturation_positive=call(ev,rid,token,run_labels,jwt=jwt)
       if saturation_positive["status"]!=200:
        raise RuntimeError(f"saturation positive control failed: {saturation_positive}")
       docker("pause","andyur-wire-backend")
       flood=f"""import concurrent.futures,httpx,json,os
def one(_):
 try:
  h={{'X-Andyur-Run-Token':os.environ['T'],'Authorization':'Bearer '+os.environ['J']}}
  with httpx.Client(transport=httpx.HTTPTransport(uds='/run/egress/state.sock'),timeout=2,trust_env=False) as c:return c.get('http://andyur-broker-state'+os.environ['P'],headers=h).status_code
 except Exception:return 0
with concurrent.futures.ThreadPoolExecutor(max_workers=96) as p:print(json.dumps(list(p.map(one,range(96)))))"""
       codes=json.loads(py("andyur-wire-client",flood,vols=(f"{ev}:/run/egress",),
        env={"T":token,"J":jwt,"P":f"/runs/{rid}/broker-state"},timeout=20).stdout.splitlines()[-1])
       # BOUNDED RECOVERY, not a fixed 2s. The assertion below is that the
       # broker RECOVERS after the flood, so sleeping a guess and taking one
       # sample tests how fast this host is as much as it tests recovery.
       docker("unpause","andyur-wire-backend")
       recovered=None
       rdeadline=time.monotonic()+60
       while time.monotonic()<rdeadline:
        recovered=call(ev,rid,token,run_labels,jwt=jwt)
        if recovered["status"]==200: break
        time.sleep(1)
       distribution={str(code):codes.count(code) for code in sorted(set(codes))}
       if recovered["status"]!=200 or any(x==200 for x in codes):
        raise RuntimeError(f"authenticated saturation/recovery failed: {distribution}")
       halt=f"from andyur import db\nwith db.connect() as c:c.execute(\"UPDATE runs SET state='failed' WHERE id=?\",({rid!r},))"
       docker("exec","-i","andyur-wire-backend","python","-",input_text=halt)
       stopped=call(ev,rid,token,run_labels,jwt=jwt)
       if stopped["status"]!=401:raise RuntimeError(f"halt replay accepted: {stopped}")
       result.update({"positive":{"status":200,"state":state,"forged_xfcc_sanitized":True},
        "wrong_peer_replay":{"status":403,"captured_jwt_replayed":True},
        "identity_mutation_red_restored":{"mutation_applied":True,
          "forged_peer_accepted_status":200,"restored_refusal_status":403},
        "sds_rotation":{"before":before,"after":after,"rotated":True},
        "run_context":{"run_id":rid,"wrong_run_id":wrong,"agent":agent,
          "expected_actor":rs,"wrong_actor":ws,"control_plane":cs},
        "saturation":{"authenticated_positive_status":200,"requests":len(codes),
          "refused":sum(x!=200 for x in codes),"status_distribution":distribution,
          "recovered_status":200},
        "halt_replay":{"status":401,"run_state":"failed"}})
    finally:
      clean()
      for v in vols:docker("volume","rm",v,check=False)
      run("bash",str(SPIRE),"down",check=False,timeout=60)
    if any(docker("inspect",n,check=False).returncode==0 for n in NAMES):raise RuntimeError("container teardown incomplete")
    result.update({"started_at_epoch":started,"finished_at_epoch":time.time(),
      "platform":platform.platform(),"envoy_image":ENVOY,"server_image":IMAGE,
      "server_image_id":image_id,"executed_source_sha256":executed,
      "teardown":{"containers_absent":True,"volumes_absent":True,"spire_down":True},
      "source_sha256":{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sorted(SOURCES)}})
    rendered=json.dumps(result,indent=2,sort_keys=True)+"\n"
    RESULT.write_text(rendered)
    print(rendered,end="")
if __name__=="__main__":main()
