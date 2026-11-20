"""Assignment 5 CO5 safe synthetic network-security simulation."""
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class Packet:
    src:str; dst:str; sport:int; dport:int; proto:str; direction:str; payload:str=""

class Rule:
    def __init__(self,name,action,predicate): self.name,self.action,self.predicate=name,action,predicate
    def __call__(self,p): return self.predicate(p)

def rules(order="original"):
    r=[
      Rule("DENY_TELNET","DROP",lambda p:p.proto=="TCP" and p.dport==23),
      Rule("ALLOW_DNS_OUT","ALLOW",lambda p:p.direction=="OUT" and p.proto=="UDP" and p.dport==53),
      Rule("ALLOW_HTTPS_OUT","ALLOW",lambda p:p.direction=="OUT" and p.proto=="TCP" and p.dport==443),
      Rule("ALLOW_HTTP_OUT","ALLOW",lambda p:p.direction=="OUT" and p.proto=="TCP" and p.dport==80),
      Rule("ALLOW_ICMP_OUT","ALLOW",lambda p:p.direction=="OUT" and p.proto=="ICMP")]
    return [r[0],r[2],r[1],r[3],r[4]] if order=="reordered" else r

class StatefulFirewall:
    def __init__(self,ordered_rules,timeout=5):
        self.rules=ordered_rules; self.timeout=timeout; self.table={}; self.stats=defaultdict(int); self.now=0
    def key(self,p): return (p.src,p.sport,p.dst,p.dport,p.proto)
    def process(self,p,t):
        self.now=t
        for k,last in list(self.table.items()):
            if t-last>self.timeout: del self.table[k]; self.stats["expired"]+=1
        self.stats["packets"]+=1
        reverse=(p.dst,p.dport,p.src,p.sport,p.proto)
        if p.direction=="IN" and reverse in self.table:
            self.table[reverse]=t; self.stats["state_hits"]+=1; self.stats["allowed"]+=1
            return "ALLOW","ESTABLISHED_RETURN",0
        checks=0; action="DROP"; matched="DEFAULT_DROP"
        for rule in self.rules:
            checks+=1
            if rule(p): action,matched=rule.action,rule.name; break
        self.stats["rule_evaluations"]+=checks
        if action=="ALLOW":
            self.stats["allowed"]+=1
            if p.direction=="OUT" and p.proto in ("TCP","UDP"):
                self.table[self.key(p)]=t; self.stats["created"]+=1
        else: self.stats["dropped"]+=1
        return action,matched,checks

def firewall():
    print("\\n[B1] STATEFUL FIREWALL")
    fw=StatefulFirewall(rules())
    tests=[
      Packet("10.0.0.10","93.184.216.34",51000,443,"TCP","OUT"),
      Packet("93.184.216.34","10.0.0.10",443,51000,"TCP","IN"),
      Packet("203.0.113.9","10.0.0.10",40000,22,"TCP","IN"),
      Packet("10.0.0.10","198.51.100.8",52000,23,"TCP","OUT"),
      Packet("10.0.0.10","8.8.8.8",53000,53,"UDP","OUT"),
      Packet("10.0.0.10","192.0.2.7",54000,8080,"TCP","OUT")]
    for i,p in enumerate(tests,1):
        a,m,c=fw.process(p,i); print(f"packet {i}: {p.direction} {p.proto}/{p.dport} -> {a} ({m}), checks={c}")
    print("counters:",dict(fw.stats)); print("connection_table_size:",len(fw.table))
    traffic=[Packet("10.0.0.2",f"198.51.100.{i%200+1}",40000+i,443,"TCP","OUT") for i in range(200)]
    totals={}
    for o in ("original","reordered"):
        x=StatefulFirewall(rules(o))
        for i,p in enumerate(traffic): x.process(p,i)
        totals[o]=x.stats["rule_evaluations"]
    print("200-packet rule-evaluation comparison:",totals)

def ids():
    print("\\n[B3] IDS SIGNATURE AND ANOMALY DETECTION")
    sigs=[
      ("HTTP_MARKER","TCP",80,"IN","TEST-MALWARE"),
      ("DNS_MARKER","UDP",53,"OUT","DNS-TEST"),
      ("SSH_BRUTE","TCP",22,"IN","AUTH-FAIL"),
      ("SMTP_SPAM","TCP",25,"OUT","SPAM-TEST"),
      ("TELNET_MARKER","TCP",23,"IN","LOGIN-TEST")]
    ev=[
      Packet("198.51.100.2","10.0.0.5",50000,80,"TCP","IN","GET / TEST-MALWARE"),
      Packet("10.0.0.5","8.8.8.8",53000,53,"UDP","OUT","ordinary query"),
      Packet("198.51.100.3","10.0.0.5",50001,443,"TCP","IN","ordinary HTTPS")]
    payload_checks=alerts=0
    for i,p in enumerate(ev,1):
        hit=None
        for name,proto,port,direction,marker in sigs:
            if (p.proto,p.dport,p.direction)!=(proto,port,direction): continue
            payload_checks+=1
            if marker in p.payload: hit=name; alerts+=1; break
        print(f"event {i}: candidate_payload_checks={payload_checks}, alert={hit or 'NONE'}")
    print(f"signatures={len(sigs)}, events={len(ev)}, alerts={alerts}")
    print("fragmented marker caveat: requires stream reassembly and protocol normalization.")
    print("sliding-window scan detector:")
    window,threshold=10,5; history=defaultdict(deque)
    scan=[("10.0.0.20",f"192.0.2.{i}",80,i) for i in range(1,6)]+[("10.0.0.21","192.0.2.8",443,6)]
    for src,dst,port,t in scan:
        q=history[src]
        while q and t-q[0][2]>window:q.popleft()
        q.append((dst,port,t)); hosts=len({x[0] for x in q}); ports=len({x[1] for x in q})
        print(f"t={t} src={src} distinct_hosts={hosts} distinct_ports={ports} -> {'ALERT' if hosts>=threshold else 'LOG'}")

def worm():
    print("\\n[B4] 200-HOST WORM CONTAINMENT SIMULATION")
    def simulate(strategy):
        infected=1; values=[1]
        for step in range(1,9):
            new=min(200-infected,infected*2)
            if strategy=="rate_limit" and step>=2:new=int(new*.5)
            if strategy=="segmentation" and step>=2:new=int(new*.25)
            infected=min(200,infected+new); values.append(infected)
            if infected==200:break
        return values
    for s in ("none","rate_limit","segmentation"):
        v=simulate(s); t50=next((i for i,n in enumerate(v) if n>=100),None); t100=next((i for i,n in enumerate(v) if n>=200),None)
        print(f"{s}: infections_per_step={v}; step_50pct={t50}; step_100pct={t100}")
    print("limitation: perimeter-only blocking cannot stop lateral spread over permitted internal channels.")

def web_tls_set():
    print("\\n[CO5] TLS POLICY AND SET DESIGN")
    for label,ok in [("TLS 1.3 negotiated",1),("trusted certificate chain",1),("hostname mismatch",0),("expired certificate",0),("obsolete SSL/TLS version",0)]:
        print(f"{label}: {'ACCEPT' if ok else 'REJECT'}")
    print("SET participants: cardholder, merchant, issuer, acquirer, payment gateway, certificate authority.")
    print("SET dual signature links order and payment data while separating what merchant and gateway can view.")

def main():
    print("ASSIGNMENT 5 CO5 – SAFE SYNTHETIC LAB; no real packets or malware.")
    firewall(); ids(); worm(); web_tls_set()
    print("\\nAll simulation modules completed.")
if __name__=="__main__": main()
