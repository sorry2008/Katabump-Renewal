#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse PROXY_URL (single URI or subscription) and generate sing-box config."""
import base64, copy, json, os, re, sys
from urllib.parse import urlparse, parse_qs, unquote

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080
TEST_URL = "https://www.gstatic.com/generate_204"
SUPPORTED = {"vless","vmess","trojan","hysteria2","hy2","anytls","tuic","socks5","socks","http","https"}

def first(p,*names,default=""):
    for n in names:
        v=p.get(n)
        if v is not None and v != "": return v[0] if isinstance(v,list) else v
    return default

def boolean(v): return str(v).lower() in ("1","true","yes","on") if not isinstance(v,bool) else v

def i(v,d):
    try:return int(v)
    except:return d

def tls_params(p, default=True):
    security=first(p,"security",default="")
    if not (default or security in ("tls","reality")): return None
    t={"enabled":True}
    sni=first(p,"sni","servername","server_name","peer",default="")
    if sni:t["server_name"]=unquote(str(sni))
    fp=first(p,"fp","client-fingerprint","fingerprint",default="")
    if fp:t["utls"]={"enabled":True,"fingerprint":fp}
    alpn=first(p,"alpn",default="")
    if alpn:t["alpn"]=[x.strip() for x in str(alpn).split(",") if x.strip()]
    if boolean(first(p,"insecure","allowInsecure",default="0")):t["insecure"]=True
    if security=="reality" or first(p,"pbk",default=""):
        r={"enabled":True}
        pbk=first(p,"pbk","public-key","public_key",default="")
        sid=first(p,"sid","short-id","short_id",default="")
        if pbk:r["public_key"]=pbk
        if sid:r["short_id"]=sid
        t["reality"]=r
    return t

def transport(p):
    n=first(p,"type","network","net",default="").lower()
    if n in ("ws","websocket"):
        t={"type":"ws"}; path=first(p,"path",default=""); host=first(p,"host","ws-host",default="")
        if path:t["path"]=unquote(path)
        if host:t["headers"]={"Host":host}
        return t
    if n=="grpc":
        t={"type":"grpc"}; s=first(p,"serviceName","service_name","grpc-service-name",default="")
        if s:t["service_name"]=s
        return t
    if n in ("h2","http"):
        t={"type":"http"}; path=first(p,"path",default=""); host=first(p,"host",default="")
        if path:t["path"]=unquote(path)
        if host:t["host"]= [host]
        return t
    return None

def parse_uri(uri):
    uri=uri.strip().strip("\"'").rstrip(",;)")
    p=urlparse(uri); s=p.scheme.lower()
    if s not in SUPPORTED: raise ValueError("unsupported scheme")
    if s=="vmess": return parse_vmess(uri)
    q=parse_qs(p.query,keep_blank_values=True)
    if s in ("socks5","socks"):
        o={"type":"socks","tag":"proxy","server":p.hostname,"server_port":p.port or 1080,"version":"5"}
        if p.username:o["username"]=unquote(p.username)
        if p.password:o["password"]=unquote(p.password)
        return o
    if s in ("http","https"):
        o={"type":"http","tag":"proxy","server":p.hostname,"server_port":p.port or 8080}
        if p.username:o["username"]=unquote(p.username)
        if p.password:o["password"]=unquote(p.password)
        if s=="https":o["tls"]={"enabled":True}
        return o
    if s=="vless":
        o={"type":"vless","tag":"proxy","server":p.hostname,"server_port":p.port or 443,"uuid":unquote(p.username or "")}
        if not o["uuid"]:raise ValueError("empty vless uuid")
        flow=first(q,"flow",default="")
        if flow:o["flow"]=flow
        t=tls_params(q,False)
        if t:o["tls"]=t
        tr=transport(q)
        if tr:o["transport"]=tr
        return o
    if s=="trojan":
        o={"type":"trojan","tag":"proxy","server":p.hostname,"server_port":p.port or 443,"password":unquote(p.username or "")}
        if not o["password"]:raise ValueError("empty trojan password")
        o["tls"]=tls_params(q,True); tr=transport(q)
        if tr:o["transport"]=tr
        return o
    if s in ("hy2","hysteria2"):
        o={"type":"hysteria2","tag":"proxy","server":p.hostname,"server_port":p.port or 443,"password":unquote(p.username or "")}
        if not o["password"]:raise ValueError("empty hysteria2 password")
        o["tls"]=tls_params(q,True)
        ob=first(q,"obfs",default="")
        if ob:o["obfs"]={"type":ob,"password":first(q,"obfs-password","obfs_password",default="")}
        return o
    if s=="anytls":
        o={"type":"anytls","tag":"proxy","server":p.hostname,"server_port":p.port or 443,"password":unquote(p.username or "")}
        if not o["password"]:raise ValueError("empty anytls password")
        o["tls"]=tls_params(q,True); return o
    if s=="tuic":
        u=unquote(p.username or ""); pw=unquote(p.password or "")
        if ":" in u and not pw:u,pw=u.split(":",1)
        o={"type":"tuic","tag":"proxy","server":p.hostname,"server_port":p.port or 443,"uuid":u,"password":pw,"congestion_control":first(q,"congestion_control","congestion-control",default="bbr")}
        o["tls"]=tls_params(q,True); return o

def b64decode(s):
    s=re.sub(r"\s+","",s).replace("-","+").replace("_","/"); s += "="*((4-len(s)%4)%4)
    return base64.b64decode(s).decode("utf-8-sig",errors="replace")

def parse_vmess(uri):
    cfg=json.loads(b64decode(uri.split("://",1)[1]))
    o={"type":"vmess","tag":cfg.get("ps") or "proxy","server":cfg.get("add") or cfg.get("server"),"server_port":i(cfg.get("port"),443),"uuid":cfg.get("id", ""),"security":cfg.get("scy","auto") or "auto","alter_id":i(cfg.get("aid"),0)}
    if not o["server"]:raise ValueError("empty vmess server")
    if str(cfg.get("tls","")).lower()=="tls" or cfg.get("sni"):
        t={"enabled":True}; sni=cfg.get("sni") or cfg.get("host")
        if sni:t["server_name"]=sni
        if cfg.get("alpn"):t["alpn"]=cfg["alpn"] if isinstance(cfg["alpn"],list) else [x.strip() for x in str(cfg["alpn"]).split(",")]
        o["tls"]=t
    n=str(cfg.get("net","tcp")).lower()
    if n=="ws":
        t={"type":"ws"};
        if cfg.get("path"):t["path"]=cfg["path"]
        if cfg.get("host"):t["headers"]={"Host":cfg["host"]}
        o["transport"]=t
    elif n=="grpc":
        t={"type":"grpc"};
        if cfg.get("path"):t["service_name"]=cfg["path"]
        o["transport"]=t
    elif n in ("h2","http"):
        t={"type":"http"};
        if cfg.get("path"):t["path"]=cfg["path"]
        if cfg.get("host"):t["host"]=[cfg["host"]]
        o["transport"]=t
    return o

URI_RE=re.compile(r"(?i)\b(?:vless|vmess|trojan|hysteria2|hy2|anytls|tuic|socks5|socks|https?|http)://[^\s<>\[\]\"'`]+")

def decode_candidates(body):
    text=body.decode("utf-8-sig",errors="replace") if isinstance(body,bytes) else str(body)
    c=[text]
    u=unquote(text)
    if u!=text:c.append(u)
    for x in list(c):
        try:
            d=b64decode(x.strip())
            if any(k in d.lower() for k in ("vless://","vmess://","trojan://","hysteria2://","hy2://","anytls://","tuic://","socks5://","proxies:","\"proxies\"")):c.append(d)
        except:pass
    return c

def clash_to_ob(n):
    if not isinstance(n,dict):return None
    typ=str(n.get("type","")).lower(); server=n.get("server") or n.get("add"); port=i(n.get("port"),443); name=n.get("name") or n.get("ps") or "proxy"
    if not server:return None
    if typ in ("socks","socks5"):
        o={"type":"socks","tag":name,"server":server,"server_port":port,"version":"5"}
        for k in ("username","password"):
            if n.get(k) is not None:o[k]=str(n[k])
        return o
    if typ in ("http","https"):
        o={"type":"http","tag":name,"server":server,"server_port":port}
        for k in ("username","password"):
            if n.get(k) is not None:o[k]=str(n[k])
        if typ=="https":o["tls"]={"enabled":True}
        return o
    if typ in ("trojan","vless","hysteria2","hy2","tuic","anytls","vmess"):
        # Normalize Clash/Mihomo nodes into URI-like sing-box structures.
        if typ=="trojan":
            o={"type":"trojan","tag":name,"server":server,"server_port":port,"password":str(n.get("password","")),"tls":{"enabled":True}}
            s=n.get("sni") or n.get("servername");
            if s:o["tls"]["server_name"]=str(s)
            if n.get("skip-cert-verify"):o["tls"]["insecure"]=True
            return o
        if typ=="vless":
            o={"type":"vless","tag":name,"server":server,"server_port":port,"uuid":str(n.get("uuid") or n.get("id") or "")}
            if n.get("flow"):o["flow"]=str(n["flow"])
            if n.get("tls") or n.get("servername") or n.get("sni"):
                o["tls"]={"enabled":True}; s=n.get("servername") or n.get("sni")
                if s:o["tls"]["server_name"]=str(s)
                if n.get("skip-cert-verify"):o["tls"]["insecure"]=True
            return o
        if typ in ("hysteria2","hy2"):
            o={"type":"hysteria2","tag":name,"server":server,"server_port":port,"password":str(n.get("password","")),"tls":{"enabled":True}}
            s=n.get("sni") or n.get("servername")
            if s:o["tls"]["server_name"]=str(s)
            if n.get("skip-cert-verify"):o["tls"]["insecure"]=True
            return o
        if typ=="tuic":
            return {"type":"tuic","tag":name,"server":server,"server_port":port,"uuid":str(n.get("uuid","")),"password":str(n.get("password","")),"congestion_control":str(n.get("congestion-controller","bbr")),"tls":{"enabled":True,"server_name":str(n.get("sni") or n.get("servername") or "")}}
        if typ=="anytls":
            o={"type":"anytls","tag":name,"server":server,"server_port":port,"password":str(n.get("password","")),"tls":{"enabled":True}}
            s=n.get("sni") or n.get("servername");
            if s:o["tls"]["server_name"]=str(s)
            return o
        # vmess
        raw={"add":server,"port":port,"id":n.get("uuid") or n.get("id"),"aid":n.get("alterId",n.get("alter-id",0)),"scy":n.get("cipher","auto"),"tls":"tls" if n.get("tls") else "","sni":n.get("servername") or n.get("sni"),"net":n.get("network","tcp")}
        return dict(parse_vmess("vmess://"+base64.b64encode(json.dumps(raw).encode()).decode()),tag=name)
    return None

def parse_fallback_yaml(text):
    lines=text.replace("\r\n","\n").split("\n"); start=None
    for j,l in enumerate(lines):
        if re.match(r"^\s*proxies\s*:\s*$",l,re.I):start=j+1;break
    if start is None:return []
    out=[]; cur=None
    for l in lines[start:]:
        if l and not l.startswith((" ","\t")):break
        m=re.match(r"^\s*-\s*(.*)$",l)
        if m:
            if cur:out.append(cur)
            cur={}; rest=m.group(1)
            if ":" in rest:
                k,v=rest.split(":",1);cur[k.strip()]=v.strip().strip("\"'")
        elif cur:
            m=re.match(r"^\s+([^:#][^:]*):\s*(.*)$",l)
            if m:cur[m.group(1).strip()]=m.group(2).strip().strip("\"'")
    if cur:out.append(cur)
    return out

def collect(body):
    obs=[]; seen=set()
    def add(o):
        if not o or not o.get("server"):return
        key=(o.get("type"),o.get("server"),o.get("server_port"),o.get("uuid"),o.get("password"))
        if key in seen:return
        seen.add(key); o["tag"]=o.get("tag") or "node-%d"%(len(obs)+1);obs.append(o)
    for text in decode_candidates(body):
        for uri in URI_RE.findall(text):
            try:add(parse_uri(uri))
            except:pass
        try:
            import yaml
            obj=yaml.safe_load(text)
        except:
            try:obj=json.loads(text)
            except:obj=None
        if isinstance(obj,dict):
            vals=[]
            for k in ("proxies","nodes","outbounds","servers"):
                if isinstance(obj.get(k),list):vals += obj[k]
            for n in vals:add(clash_to_ob(n))
        elif isinstance(obj,list):
            for n in obj:add(clash_to_ob(n))
        for n in parse_fallback_yaml(text):add(clash_to_ob(n))
    return obs

def fetch(url):
    import ssl, urllib.request
    req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 Katabump-Renewal","Accept":"*/*","Cache-Control":"no-cache"})
    ctx=ssl.create_default_context()
    if boolean(os.environ.get("SUBSCRIPTION_INSECURE","0")):
        ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    with urllib.request.urlopen(req,timeout=30,context=ctx) as r:return r.read()

def load_pool():
    f=os.environ.get("POOL_FILE","pool.json")
    if not os.path.exists(f):return []
    try:
        with open(f,encoding="utf-8") as h:d=json.load(h)
        return [x for x in d if isinstance(x,dict) and x.get("server") and x.get("port")]
    except:return []

def config(obs):
    if len(obs)==1:obs[0]["tag"]="proxy"; outs=obs+[ {"type":"direct","tag":"direct"} ]
    else:
        for j,o in enumerate(obs,1):o["tag"]=o.get("tag") or "node-%d"%j
        outs=obs+[{"type":"urltest","tag":"proxy","outbounds":[o["tag"] for o in obs],"url":TEST_URL,"interval":"30s","tolerance":50},{"type":"direct","tag":"direct"}]
    return {"log":{"level":"info","timestamp":True},"inbounds":[{"type":"http","tag":"http-in","listen":LISTEN_HOST,"listen_port":LISTEN_PORT}],"outbounds":outs,"route":{"final":"proxy"}}

def write(obs):
    with open("config.json","w",encoding="utf-8") as f:json.dump(config(obs),f,indent=2,ensure_ascii=False)
    print("sing-box config.json generated.")
    print("  Inbound: http://%s:%d"%(LISTEN_HOST,LISTEN_PORT));print("  Nodes: %d"%len(obs));print("  Selector: urltest -> proxy")

def main():
    url=os.environ.get("PROXY_URL","").strip()
    if not url:return 0
    scheme=url.split("://",1)[0].lower()
    if scheme in {"vless","vmess","trojan","hysteria2","hy2","anytls","tuic","socks5","socks"}:
        try:o=parse_uri(url);obs=[o]
        except Exception as e:print("Error: %s"%e);return 1
        if o["type"]=="anytls" and load_pool():
            base=o;obs=[]
            for j,n in enumerate(load_pool(),1):
                x=copy.deepcopy(base);x["tag"]="node-%d"%j;x["server_port"]=int(n["port"])
                if n.get("server"):x["server"]=n["server"]
                if n.get("sni"):x.setdefault("tls",{})["server_name"]=n["sni"]
                obs.append(x)
        write(obs);return 0
    if scheme in ("http","https"):
        print("Subscription mode: downloading subscription...")
        print("  URL: %s"%(url.split("?",1)[0]+("***" if "?" in url else "")))
        try:body=fetch(url)
        except Exception as e:print("Error: failed to download subscription: %s"%e);return 1
        print("  Subscription downloaded: %d bytes"%len(body))
        obs=collect(body)
        if not obs:
            print("Subscription downloaded, but no supported proxy node was found.")
            print("Supported: vless / vmess / trojan / hysteria2 / anytls / tuic / socks5 / http")
            print("Subscription formats: plain URI / base64 / YAML / JSON")
            return 1
        print("Found %d supported proxy node(s)."%len(obs));write(obs);return 0
    print("Unsupported PROXY_URL scheme: %s"%scheme);return 1

if __name__=="__main__":sys.exit(main())
