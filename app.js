const STORAGE_KEY = "socL1PracticeLab.v3";
const LEGACY_STORAGE_KEY = "socL1PracticeLab.v2";
const STORAGE_VERSION = 3;
const DATASET_SIZE = 560;
const MAX_SCORE = 6;
const EVIDENCE_TABS = ["overview", "timeline", "process", "network", "auth", "intel", "scope", "raw"];

const state = {
  alerts: [],
  datasetSeed: Date.now(),
  selectedId: null,
  page: 1,
  pageSize: 40,
  storageAvailable: true
};

const ASSETS = [
  {hostname:"DC-01",ip:"10.10.1.10",os:"Windows Server 2022",criticality:"Critical",department:"Identity",edrStatus:"Healthy"},
  {hostname:"SRV-DB-03",ip:"10.10.3.23",os:"Windows Server 2019",criticality:"Critical",department:"Finance",edrStatus:"Healthy"},
  {hostname:"SRV-WEB-02",ip:"10.10.4.22",os:"Ubuntu 22.04",criticality:"High",department:"E-Commerce",edrStatus:"Degraded"},
  {hostname:"SRV-APP-02",ip:"10.10.4.17",os:"Windows Server 2022",criticality:"High",department:"Applications",edrStatus:"Healthy"},
  {hostname:"VPN-GW-01",ip:"10.10.0.5",os:"Network Appliance",criticality:"Critical",department:"Infrastructure",edrStatus:"N/A"},
  {hostname:"WIN-FIN-07",ip:"10.20.10.37",os:"Windows 11",criticality:"High",department:"Finance",edrStatus:"Healthy"},
  {hostname:"WIN-HR-14",ip:"10.20.20.44",os:"Windows 11",criticality:"High",department:"Human Resources",edrStatus:"Healthy"},
  {hostname:"LAP-DEV-17",ip:"10.20.30.57",os:"Windows 11",criticality:"Medium",department:"Engineering",edrStatus:"Healthy"},
  {hostname:"LAP-SALES-11",ip:"10.20.40.51",os:"Windows 11",criticality:"Medium",department:"Sales",edrStatus:"Sensor stale"},
  {hostname:"WIN-OPS-09",ip:"10.20.50.39",os:"Windows 10",criticality:"Medium",department:"Operations",edrStatus:"Healthy"},
  {hostname:"WIN-3G9P2Q1",ip:"10.20.60.31",os:"Windows 11",criticality:"Low",department:"Contractors",edrStatus:"Healthy"},
  {hostname:"MAIL-01",ip:"10.10.5.15",os:"Exchange Online",criticality:"Critical",department:"Infrastructure",edrStatus:"N/A"}
];

const IDENTITIES = [
  {username:"jsingh",privilege:"Standard",department:"Finance",mfa:"Enabled",accountAge:"4 years"},
  {username:"rmehta",privilege:"Standard",department:"Human Resources",mfa:"Enabled",accountAge:"2 years"},
  {username:"akumar",privilege:"Local Admin",department:"Engineering",mfa:"Enabled",accountAge:"5 years"},
  {username:"mverma",privilege:"Standard",department:"Sales",mfa:"Enabled",accountAge:"18 months"},
  {username:"nsharma",privilege:"Standard",department:"Operations",mfa:"Enabled",accountAge:"3 years"},
  {username:"priya",privilege:"Standard",department:"Finance",mfa:"Enabled",accountAge:"9 months"},
  {username:"admin-support",privilege:"Domain Admin",department:"IT",mfa:"Enabled",accountAge:"6 years"},
  {username:"helpdesk01",privilege:"Local Admin",department:"IT",mfa:"Enabled",accountAge:"4 years"},
  {username:"websvc",privilege:"Service",department:"Applications",mfa:"Not applicable",accountAge:"3 years"},
  {username:"svc_backup",privilege:"Service",department:"Infrastructure",mfa:"Not applicable",accountAge:"5 years"},
  {username:"svc_scanner",privilege:"Service",department:"Security",mfa:"Not applicable",accountAge:"2 years"},
  {username:"user.j.smith",privilege:"Standard",department:"Contractors",mfa:"Disabled",accountAge:"3 months"}
];

const GEO = [
  ["Amsterdam, NL","AS9009 M247"],["Moscow, RU","AS49505 Selectel"],["Lagos, NG","AS29465 MTN"],
  ["Frankfurt, DE","AS24940 Hetzner"],["Ashburn, US","AS14618 Amazon"],["Singapore, SG","AS14061 DigitalOcean"],
  ["Mumbai, IN","AS55836 Reliance"],["Delhi, IN","AS9498 Airtel"],["Bengaluru, IN","AS24560 Bharti"]
];

const ACTIONS = [
  "Escalate to L2 / Incident Response",
  "Contain Host and Escalate",
  "Disable Account and Escalate",
  "Block IOC and Monitor",
  "Request More Logs / Enrichment",
  "Close as False Positive",
  "Monitor Only"
];

function hashString(value){let h=2166136261;for(const ch of String(value)){h^=ch.charCodeAt(0);h=Math.imul(h,16777619)}return h>>>0}
function rngFrom(seed){let a=seed>>>0;return()=>{a+=0x6D2B79F5;let t=a;t=Math.imul(t^t>>>15,t|1);t^=t+Math.imul(t^t>>>7,t|61);return((t^t>>>14)>>>0)/4294967296}}
function pick(rng,arr){return arr[Math.floor(rng()*arr.length)]}
function int(rng,min,max){return Math.floor(rng()*(max-min+1))+min}
function chance(rng,p){return rng()<p}
function pad(n){return String(n).padStart(2,"0")}
function formatDateTime(iso){const d=new Date(iso);return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`}
function nowStamp(){return new Date().toLocaleString()}
function escapeHTML(value){return String(value??"").replace(/[&<>'"]/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[ch]))}
function sevDot(sev){const color=sev==="Critical"?"var(--red)":sev==="High"?"var(--orange)":sev==="Medium"?"var(--yellow)":"var(--green)";return `<span class="dot" style="background:${color}"></span>`}
function riskClass(score){return score>=85?"risk-critical":score>=65?"risk-high":score>=40?"risk-medium":"risk-low"}
function externalIp(rng){const block=pick(rng,["198.51.100","203.0.113","192.0.2"]);return `${block}.${int(rng,2,253)}`}
function internalIp(rng){return `10.${int(rng,10,30)}.${int(rng,1,60)}.${int(rng,2,250)}`}
function fakeHash(rng,length=64){const chars="abcdef0123456789";return Array.from({length},()=>chars[Math.floor(rng()*chars.length)]).join("")}
function timeAt(c,offsetSeconds){return formatDateTime(new Date(new Date(c.detectedAt).getTime()+offsetSeconds*1000).toISOString())}
function timeline(c,offset,event,source,significance){return {time:timeAt(c,offset),event,source,significance}}
function authRow(c,offset,eventId,type,result,ip,device,mfa="N/A"){return {time:timeAt(c,offset),eventId,type,result,ip,device,mfa}}
function netRow(c,offset,src,dest,port,protocol,direction,bytes,assessment){return {time:timeAt(c,offset),src,dest,port:String(port),protocol,direction,bytes,assessment}}
function proc(image,pid,parent,command,signature,verdict,hash="—"){return {image,pid:String(pid),parent,command,signature,verdict,hash}}
function scopeRow(entity,type,alerts,lastSeen,status){return {entity,type,alerts:String(alerts),lastSeen,status}}
function makeIntel(c,ioc,score,verdict,tags=[],known=false){const [geo,asn]=pick(c.rng,GEO);return {ioc,score,verdict,reports:int(c.rng,score>70?12:0,score>70?48:8),geo,asn,firstSeen:`${int(c.rng,1,known?900:75)} days ago`,tags,internalPrevalence:known?`${int(c.rng,12,75)} hosts`:pick(c.rng,["Never seen","1 host","2 hosts"]),allowlisted:known}}
function expected(classification,severity,action,ipAssessment,endpointImpact,compromise){return {classification,severity,action,ipAssessment,endpointImpact,compromise}}

function buildContext(index,datasetSeed,scenarioIndex){
  const seed=hashString(`${datasetSeed}:${index}:${scenarioIndex}`),rng=rngFrom(seed);
  const detectedAt=new Date(Date.now()-int(rng,0,48*60*60)*1000-index*137).toISOString();
  return {index,seed,rng,detectedAt,host:{...pick(rng,ASSETS)},user:{...pick(rng,IDENTITIES)}};
}

const SCENARIOS = [
  {
    key:"auth_bruteforce",ruleId:"AUTH-1001",product:"Microsoft Sentinel",dataSource:"Identity / VPN",mitre:"Credential Access",technique:"T1110 Brute Force",
    build(c){
      const service=pick(c.rng,["VPN","RDP","SSH","Microsoft 365"]),failed=int(c.rng,18,486),minutes=int(c.rng,2,37),successes=chance(c.rng,.28)?int(c.rng,1,2):0;
      const sourceIp=externalIp(c.rng),privileged=["Domain Admin","Local Admin"].includes(c.user.privilege),mfaBlocked=successes>0&&chance(c.rng,.38),compromised=successes>0&&!mfaBlocked;
      const intel=makeIntel(c,sourceIp,int(c.rng,58,96),pick(c.rng,["Suspicious","Malicious"]),["brute-force",service.toLowerCase()]);
      const severity=compromised&&privileged?"Critical":compromised||mfaBlocked||failed>250?"High":"Medium",risk=severity==="Critical"?int(c.rng,90,98):severity==="High"?int(c.rng,71,89):int(c.rng,48,69);
      const name=mfaBlocked?`${service} Brute Force Stopped by MFA`:successes?`${service} Brute Force Followed by Successful Login`:`${service} Brute Force Burst (${failed} failures)`;
      return {name,severity,riskScore:risk,confidence:successes?"High":"Medium",complexity:successes?"High":"Medium",sourceIp,intel,eventCount:failed+successes,logCompleteness:pick(c.rng,["92%","96%","100%"]),
        summary:`${failed} failed ${service} logins from ${sourceIp} targeted ${c.user.username} in ${minutes} minutes${successes?`, followed by ${successes} successful login${successes>1?"s":""}`:" with no confirmed success"}.`,
        overview:[{label:"Failed logins",value:String(failed),tone:"danger"},{label:"Window",value:`${minutes} minutes`},{label:"Successful logins",value:String(successes),tone:successes?"danger":"good"},{label:"Account privilege",value:c.user.privilege},{label:"MFA result",value:mfaBlocked?"Challenge blocked":compromised?"Not challenged":"No success"},{label:"Source prevalence",value:intel.internalPrevalence}],
        timeline:[timeline(c,-minutes*60,`${service} failures begin`,"Authentication",`${failed} total failures`),timeline(c,-95,"Failure velocity crosses rule threshold","SIEM","Correlation triggered"),...(successes?[timeline(c,-44,mfaBlocked?"Login attempt challenged and blocked by MFA":"Successful login from same source","Authentication",mfaBlocked?"No session issued":"Session issued")]:[]),timeline(c,0,"SOC alert created","SIEM",`Risk ${risk}/100`)],
        process:[proc(`${service.toLowerCase()}-service`,"—","—","Authentication gateway telemetry","Vendor signed","Service context")],
        network:[netRow(c,-minutes*60,sourceIp,c.host.ip,service==="SSH"?22:service==="RDP"?3389:443,"TCP","Inbound",`${int(c.rng,2,19)} MB`,`${failed} connection attempts`)],
        auth:[authRow(c,-minutes*60,"4625",service,"Failed",sourceIp,c.host.hostname,"Not reached"),authRow(c,-90,"4625",service,"Failed",sourceIp,c.host.hostname,"Not reached"),...(successes?[authRow(c,-44,mfaBlocked?"MFAChallenge":"4624",service,mfaBlocked?"Blocked":"Success",sourceIp,c.host.hostname,mfaBlocked?"Blocked":"Not satisfied")]:[])],
        scope:[scopeRow(c.user.username,"Identity",failed,timeAt(c,-44),compromised?"Possible compromise":"Targeted"),scopeRow(c.host.hostname,"Asset",1,timeAt(c,0),compromised?"Review post-auth activity":"No endpoint evidence"),scopeRow(sourceIp,"Source IP",failed,timeAt(c,-44),intel.verdict)],
        rawLogs:[`event=auth_failure service=${service} user=${c.user.username} src_ip=${sourceIp} count=${failed} window_min=${minutes}`,`rule=AUTH-1001 result=${successes?"success_after_failures":"failures_only"} mfa=${mfaBlocked?"blocked":"not_satisfied"}`],
        expected:expected("True Positive",severity,compromised?"Disable Account and Escalate":"Block IOC and Monitor","Suspicious",compromised?"Inconclusive":"Not affected",compromised?"Confirmed":"Not confirmed")};
    }
  },
  {
    key:"impossible_travel",ruleId:"ID-2104",product:"Microsoft Entra ID",dataSource:"Cloud Identity",mitre:"Credential Access",technique:"T1078 Valid Accounts",
    build(c){
      const first=pick(c.rng,["Delhi, IN","Mumbai, IN","Bengaluru, IN"]),second=pick(c.rng,["London, GB","Toronto, CA","Singapore, SG","Frankfurt, DE"]),gap=int(c.rng,9,54),knownVpn=chance(c.rng,.42),sameDevice=chance(c.rng,.58),mfa=chance(c.rng,.72);
      const sourceIp=externalIp(c.rng),benign=knownVpn&&sameDevice&&mfa,intel=makeIntel(c,sourceIp,benign?int(c.rng,0,18):int(c.rng,24,68),benign?"Benign":"Unknown",benign?["corporate-vpn"]:["cloud-hosting"],benign);
      const severity=benign?"Low":mfa&&sameDevice?"Medium":"High",risk=benign?int(c.rng,12,29):int(c.rng,52,82);
      return {name:`Impossible Travel: ${first} → ${second}`,severity,riskScore:risk,confidence:benign?"High":"Medium",complexity:benign?"Low":"High",sourceIp,intel,eventCount:2,logCompleteness:pick(c.rng,["78%","86%","94%"]),
        summary:`Two successful cloud sign-ins for ${c.user.username} occurred ${gap} minutes apart from ${first} and ${second}. ${knownVpn?"A known corporate VPN exit is present.":"No approved VPN exit was matched."}`,
        overview:[{label:"Travel interval",value:`${gap} minutes`,tone:"danger"},{label:"First location",value:first},{label:"Second location",value:second},{label:"Device match",value:sameDevice?"Same managed device":"Different / unknown"},{label:"MFA",value:mfa?"Satisfied":"Not satisfied",tone:mfa?"good":"danger"},{label:"VPN match",value:knownVpn?"Approved exit":"No match"}],
        timeline:[timeline(c,-gap*60,`Successful sign-in from ${first}`,"Entra ID",mfa?"MFA satisfied":"Single factor"),timeline(c,-12,`Successful sign-in from ${second}`,"Entra ID",sameDevice?"Same device ID":"New device ID"),timeline(c,0,"Impossible-travel rule correlated events","SIEM",`Risk ${risk}/100`)],
        process:[proc("Cloud sign-in","—","—","No endpoint process telemetry","N/A","Identity-only alert")],
        network:[netRow(c,-12,sourceIp,"login.microsoftonline.com",443,"HTTPS","Inbound","84 KB",knownVpn?"Known VPN egress":"Unfamiliar source")],
        auth:[authRow(c,-gap*60,"EntraSignIn","Interactive","Success",internalIp(c.rng),sameDevice?c.host.hostname:"UNKNOWN-DEVICE",mfa?"Satisfied":"Not satisfied"),authRow(c,-12,"EntraSignIn","Interactive","Success",sourceIp,sameDevice?c.host.hostname:"NEW-DEVICE",mfa?"Satisfied":"Not satisfied")],
        scope:[scopeRow(c.user.username,"Identity",2,timeAt(c,-12),benign?"Consistent with VPN":"Validate with user"),scopeRow(c.host.hostname,"Device",sameDevice?2:1,timeAt(c,-12),sameDevice?"Managed":"Device mismatch")],
        rawLogs:[`category=SignInLogs user=${c.user.username} city=${first} result=success mfa=${mfa}`,`category=SignInLogs user=${c.user.username} city=${second} src_ip=${sourceIp} device_match=${sameDevice} vpn_match=${knownVpn}`],
        expected:benign?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("Needs More Investigation",severity,"Request More Logs / Enrichment",intel.score>55?"Suspicious":"Inconclusive","Inconclusive","Inconclusive")};
    }
  },
  {
    key:"powershell",ruleId:"EDR-3007",product:"Microsoft Defender for Endpoint",dataSource:"EDR Process",mitre:"Execution",technique:"T1059.001 PowerShell",
    build(c){
      const adminScript=chance(c.rng,.24),encoded=!adminScript||chance(c.rng,.55),parent=adminScript?pick(c.rng,["services.exe","CompanyRMM.exe"]):pick(c.rng,["WINWORD.EXE","EXCEL.EXE","mshta.exe"]),dest=externalIp(c.rng),sourceIp=c.host.ip;
      const intel=makeIntel(c,dest,adminScript?int(c.rng,0,12):int(c.rng,72,98),adminScript?"Benign":"Malicious",adminScript?["approved-management"]:["payload-host","c2"],adminScript);
      const severity=adminScript?"Low":chance(c.rng,.45)?"Critical":"High",risk=adminScript?int(c.rng,8,28):int(c.rng,78,97),hash=fakeHash(c.rng);
      const cmd=adminScript?`powershell.exe -File C:\\ProgramData\\IT\\Inventory-${int(c.rng,10,99)}.ps1`:`powershell.exe ${encoded?"-EncodedCommand JABXAGMAPQ...":"-nop -w hidden IEX(New-Object Net.WebClient)"}`;
      return {name:adminScript?"Approved PowerShell Inventory Script":`${encoded?"Encoded ":"Hidden "}PowerShell With Network Connection`,severity,riskScore:risk,confidence:adminScript?"High":"High",complexity:adminScript?"Low":"Medium",sourceIp,intel,eventCount:int(c.rng,4,17),logCompleteness:"100%",
        summary:`${parent} launched PowerShell on ${c.host.hostname}. ${adminScript?"The script path, signer and maintenance window match the IT allowlist.":`The command connected to rare destination ${dest} and created follow-on activity.`}`,
        overview:[{label:"Parent process",value:parent,tone:adminScript?"good":"danger"},{label:"Encoded command",value:encoded?"Yes":"No"},{label:"Script signer",value:adminScript?"Contoso IT (valid)":"Unsigned",tone:adminScript?"good":"danger"},{label:"Destination",value:dest},{label:"EDR verdict",value:adminScript?"Allowed":"Suspicious",tone:adminScript?"good":"danger"},{label:"Asset criticality",value:c.host.criticality}],
        timeline:[timeline(c,-142,`${parent} started`,"EDR","Parent observed"),timeline(c,-131,"PowerShell command executed","EDR",encoded?"Encoded content":"Hidden window"),timeline(c,-76,`TLS connection to ${dest}`,"Network","Rare destination"),...(adminScript?[]:[timeline(c,-21,"Credential discovery command observed","EDR","whoami /groups")]),timeline(c,0,"Behavior rule created alert","MDE",`Risk ${risk}/100`)],
        process:[proc(parent,int(c.rng,1200,8500),"explorer.exe",parent,adminScript?"Valid":"Valid",adminScript?"Expected":"Suspicious"),proc("powershell.exe",int(c.rng,8501,15000),parent,cmd,"Microsoft signed",adminScript?"Approved":"Malicious",hash),...(adminScript?[]:[proc("rundll32.exe",int(c.rng,15001,22000),"powershell.exe","rundll32.exe javascript:...","Microsoft signed","Suspicious")])],
        network:[netRow(c,-76,c.host.ip,dest,443,"TLS","Outbound",`${int(c.rng,140,940)} KB`,adminScript?"Approved management endpoint":"Rare / malicious destination")],
        auth:[authRow(c,-300,"4624","Interactive","Success",c.host.ip,c.host.hostname,"N/A")],
        scope:[scopeRow(c.host.hostname,"Endpoint",int(c.rng,3,9),timeAt(c,-21),adminScript?"Expected activity":"Affected"),scopeRow(c.user.username,"Identity",1,timeAt(c,-131),adminScript?"Authorized IT context":"Process owner"),scopeRow(hash.slice(0,16)+"…","SHA-256",1,timeAt(c,-131),adminScript?"Allowlisted":"Unknown hash")],
        rawLogs:[`device=${c.host.hostname} action=ProcessCreated parent=${parent} image=powershell.exe command_line="${cmd}"`, `device=${c.host.hostname} action=NetworkConnection remote_ip=${dest} remote_port=443 sha256=${hash}`],
        expected:adminScript?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("True Positive",severity,"Contain Host and Escalate","Suspicious","Confirmed","Confirmed")};
    }
  },
  {
    key:"phishing",ruleId:"MAIL-4012",product:"Email Security + EDR",dataSource:"Email / Proxy",mitre:"Initial Access",technique:"T1566.002 Spearphishing Link",
    build(c){
      const delivered=chance(c.rng,.82),clicked=delivered&&chance(c.rng,.76),submitted=clicked&&chance(c.rng,.34),payload=clicked&&chance(c.rng,.28),blocked=!delivered,domain=`${pick(c.rng,["sharepoint-doc","secure-review","invoice-view","m365-auth"])}-${int(c.rng,10,999)}.example`;
      const dest=externalIp(c.rng),intel=makeIntel(c,domain,blocked?int(c.rng,45,68):int(c.rng,70,98),blocked?"Suspicious":"Malicious",["phishing","new-domain"]),sourceIp=externalIp(c.rng);
      const confirmed=submitted||payload,severity=confirmed?"High":clicked?"Medium":"Low",risk=confirmed?int(c.rng,78,94):clicked?int(c.rng,44,69):int(c.rng,18,35);
      return {name:payload?"Phishing Link Followed by Payload Execution":submitted?"Phishing Page With Credential Submission":clicked?"User Clicked Newly Registered Domain":delivered?"Phishing Email Delivered Without Click":"Phishing Email Blocked Before Delivery",severity,riskScore:risk,confidence:confirmed?"High":"Medium",complexity:confirmed?"High":"Medium",sourceIp,intel,eventCount:int(c.rng,3,12),logCompleteness:pick(c.rng,["82%","91%","97%"]),
        summary:`A message from ${sourceIp} contained ${domain}. ${blocked?"The message was quarantined before delivery":clicked?`${c.user.username} opened the URL`:"The message was delivered but no click was recorded"}${submitted?" and submitted credentials":""}${payload?"; endpoint telemetry shows a downloaded process":""}.`,
        overview:[{label:"Delivery",value:delivered?"Delivered":"Blocked",tone:delivered?"danger":"good"},{label:"URL clicked",value:clicked?"Yes":"No"},{label:"Credentials submitted",value:submitted?"Yes":"No",tone:submitted?"danger":"good"},{label:"Payload execution",value:payload?"Observed":"Not observed",tone:payload?"danger":"good"},{label:"Domain age",value:`${int(c.rng,1,9)} days`},{label:"Mailbox",value:c.user.username}],
        timeline:[timeline(c,-420,"Message received","Email gateway",`Sender IP ${sourceIp}`),timeline(c,-398,delivered?"Message delivered":"Message quarantined","Email gateway",delivered?"Policy allowed":"Threat policy blocked"),...(clicked?[timeline(c,-172,`URL opened: ${domain}`,"Proxy","User click")]:[]),...(submitted?[timeline(c,-121,"Credential form POST observed","Proxy","Possible credential theft")]:[]),...(payload?[timeline(c,-43,"Downloaded executable started","EDR","Endpoint execution")]:[]),timeline(c,0,"Cross-source alert created","SIEM",`Risk ${risk}/100`)],
        process:clicked?[proc("OUTLOOK.EXE",int(c.rng,1100,7000),"explorer.exe","outlook.exe","Microsoft signed","Expected"),proc("msedge.exe",int(c.rng,7001,12000),"OUTLOOK.EXE",`msedge.exe https://${domain}/review`,"Microsoft signed",payload?"Suspicious chain":"User click"),...(payload?[proc("update-viewer.exe",int(c.rng,12001,19000),"msedge.exe","%TEMP%\\update-viewer.exe /silent","Unsigned","Malicious",fakeHash(c.rng))]:[])]:[],
        network:clicked?[netRow(c,-172,c.host.ip,dest,443,"HTTPS","Outbound",`${int(c.rng,20,410)} KB`,intel.verdict)]:[],
        auth:[authRow(c,-900,"EntraSignIn","Interactive","Success",c.host.ip,c.host.hostname,"Satisfied"),...(submitted?[authRow(c,120,"EntraSignIn","Interactive","Success",externalIp(c.rng),"NEW-DEVICE","Not satisfied")]:[])],
        scope:[scopeRow(c.user.username,"Mailbox",1,timeAt(c,-398),submitted?"Credential risk":"Recipient"),scopeRow(c.host.hostname,"Endpoint",payload?3:1,timeAt(c,payload?-43:-172),payload?"Affected":clicked?"No execution found":"Not affected"),scopeRow(domain,"Domain",int(c.rng,1,4),timeAt(c,-172),intel.verdict)],
        rawLogs:[`message_trace recipient=${c.user.username} sender_ip=${sourceIp} url=${domain} disposition=${delivered?"delivered":"quarantined"}`,`proxy user=${c.user.username} host=${domain} clicked=${clicked} post_credentials=${submitted}`,`edr device=${c.host.hostname} payload_executed=${payload}`],
        expected:confirmed?expected("True Positive",severity,payload?"Contain Host and Escalate":"Disable Account and Escalate","Suspicious",payload?"Confirmed":"Inconclusive","Confirmed"):blocked||!clicked?expected("True Positive",severity,"Monitor Only","Suspicious","Not affected","Not confirmed"):expected("Needs More Investigation",severity,"Request More Logs / Enrichment","Suspicious","Inconclusive","Inconclusive")};
    }
  }
];

function makeEndpointScenario(spec){
  return {
    key:spec.key,ruleId:spec.ruleId,product:"Microsoft Defender for Endpoint",dataSource:"EDR Process",mitre:spec.mitre,technique:spec.technique,
    build(c){
      const benign=chance(c.rng,spec.benignChance),variant=pick(c.rng,spec.variants),parent=pick(c.rng,benign?spec.benignParents:spec.parents),dest=externalIp(c.rng),hash=fakeHash(c.rng),sourceIp=c.host.ip;
      const severity=benign?"Low":pick(c.rng,spec.severities),risk=benign?int(c.rng,8,27):int(c.rng,spec.risk[0],spec.risk[1]);
      const intel=makeIntel(c,benign?hash:dest,benign?int(c.rng,0,15):int(c.rng,70,98),benign?"Benign":"Malicious",benign?["approved-software"]:spec.tags,benign);
      const child=benign?spec.benignImage:spec.image,command=benign?spec.benignCommand(c):spec.command(c),pid=int(c.rng,3200,19500),eventCount=int(c.rng,4,28);
      return {name:benign?spec.benignName:variant,severity,riskScore:risk,confidence:benign?"High":pick(c.rng,["Medium","High"]),complexity:benign?"Low":pick(c.rng,["Medium","High"]),sourceIp,intel,eventCount,logCompleteness:pick(c.rng,["88%","94%","100%"]),
        summary:benign?`${child} ran on ${c.host.hostname} during an approved change window; signer, path and ticket match the allowlist.`:`${parent} launched ${child} on ${c.host.hostname}. The command line and follow-on behavior match ${spec.behavior}.`,
        overview:[{label:"Parent process",value:parent,tone:benign?"good":"danger"},{label:"Image",value:child},{label:"Signer",value:benign?"Approved / valid":"Unsigned or abused binary",tone:benign?"good":"danger"},{label:"File hash",value:hash.slice(0,18)+"…"},{label:"EDR sensor",value:c.host.edrStatus},{label:"Change ticket",value:benign?`CHG-${int(c.rng,10000,99999)}`:"No match"}],
        timeline:[timeline(c,-190,`${parent} started`,"EDR","Parent observed"),timeline(c,-151,`${child} executed`,"EDR",benign?"Allowlisted path":"Suspicious command line"),timeline(c,-88,spec.followOn,"EDR / Network",benign?"Expected maintenance":"Correlated behavior"),timeline(c,0,"Behavior detection raised","MDE",`Risk ${risk}/100`)],
        process:[proc(parent,int(c.rng,1000,3199),"services.exe",parent,benign?"Valid":"Valid",benign?"Expected":"Unusual"),proc(child,pid,parent,command,benign?"Valid":"Unsigned",benign?"Approved":"Malicious",hash)],
        network:benign?[netRow(c,-88,c.host.ip,pick(c.rng,["10.10.0.12","10.10.5.20"]),443,"TLS","Internal",`${int(c.rng,20,180)} KB`,"Approved management server")]:[netRow(c,-88,c.host.ip,dest,pick(c.rng,[80,443,8443]),"TLS","Outbound",`${int(c.rng,80,1900)} KB`,"Rare / malicious destination")],
        auth:[authRow(c,-360,"4624",benign?"Service":"Interactive","Success",c.host.ip,c.host.hostname,"N/A")],
        scope:[scopeRow(c.host.hostname,"Endpoint",eventCount,timeAt(c,-88),benign?"Expected activity":"Affected"),scopeRow(c.user.username,"Identity",1,timeAt(c,-151),benign?"Authorized":"Process owner"),scopeRow(hash.slice(0,16)+"…","SHA-256",1,timeAt(c,-151),benign?"Allowlisted":"Untrusted")],
        rawLogs:[`event=ProcessCreated host=${c.host.hostname} user=${c.user.username} parent=${parent} image=${child} pid=${pid}`,`command_line="${command}" sha256=${hash} signer=${benign?"valid":"unknown"}`,`correlation=${spec.key} follow_on="${spec.followOn}"`],
        expected:benign?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("True Positive",severity,"Contain Host and Escalate","Suspicious","Confirmed","Confirmed")};
    }
  };
}

SCENARIOS.push(
  makeEndpointScenario({key:"scheduled_task",ruleId:"EDR-3108",mitre:"Persistence",technique:"T1053.005 Scheduled Task",benignChance:.18,variants:["Scheduled Task Launches Script From AppData","Suspicious Task Created Outside Change Window","Hidden Persistence Task Created"],benignName:"Approved Software Update Scheduled Task",parents:["cmd.exe","powershell.exe","wscript.exe"],benignParents:["CompanyRMM.exe","msiexec.exe"],image:"schtasks.exe",benignImage:"schtasks.exe",severities:["High","High","Critical"],risk:[72,94],tags:["persistence","task"],behavior:"unauthorized scheduled-task persistence",followOn:"New task launches from user-writable path",command:c=>`schtasks.exe /create /tn Update-${int(c.rng,10,99)} /tr %APPDATA%\\update.ps1 /sc minute`,benignCommand:c=>`schtasks.exe /create /tn CorpUpdate-${int(c.rng,10,99)} /tr C:\\Program Files\\CorpAgent\\update.exe /sc daily`}),
  makeEndpointScenario({key:"ransomware",ruleId:"EDR-5201",mitre:"Impact",technique:"T1486 Data Encrypted for Impact",benignChance:.06,variants:["Rapid File Encryption and Shadow Copy Deletion","Ransomware Behavior on Finance Endpoint","Mass File Rename Followed by Recovery Inhibition"],benignName:"Approved Backup Snapshot Maintenance",parents:["invoice-viewer.exe","update-viewer.exe","powershell.exe"],benignParents:["backup-agent.exe"],image:"vssadmin.exe",benignImage:"vssadmin.exe",severities:["Critical"],risk:[91,99],tags:["ransomware","impact"],behavior:"ransomware impact and recovery inhibition",followOn:"High-volume file modifications detected",command:c=>`vssadmin.exe delete shadows /all /quiet & cipher.exe /w:C:\\Users\\${c.user.username}`,benignCommand:c=>`vssadmin.exe resize shadowstorage /for=C: /maxsize=${int(c.rng,10,20)}%`}),
  makeEndpointScenario({key:"credential_dump",ruleId:"EDR-3309",mitre:"Credential Access",technique:"T1003 OS Credential Dumping",benignChance:.12,variants:["LSASS Memory Access by Untrusted Process","Credential Dumping via Comsvcs.dll","Security Account Manager Hive Export"],benignName:"Approved EDR Diagnostic Access to LSASS",parents:["powershell.exe","cmd.exe","procdump.exe"],benignParents:["MsSense.exe"],image:"rundll32.exe",benignImage:"MsSense.exe",severities:["Critical","High"],risk:[84,98],tags:["credential-dumping","lsass"],behavior:"credential dumping from LSASS",followOn:"Sensitive process memory handle opened",command:c=>`rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump ${int(c.rng,500,1100)} C:\\Users\\Public\\dmp.tmp full`,benignCommand:()=>"MsSense.exe -CollectDiagnostic -ProtectedProcess lsass.exe"}),
  makeEndpointScenario({key:"defense_evasion",ruleId:"EDR-6104",mitre:"Defense Evasion",technique:"T1562.001 Impair Defenses",benignChance:.2,variants:["Real-Time Protection Disabled From Command Line","EDR Service Stopped by Non-Admin Tool","Windows Event Logs Cleared"],benignName:"Approved Security Agent Maintenance",parents:["powershell.exe","cmd.exe","sc.exe"],benignParents:["CompanyRMM.exe"],image:"powershell.exe",benignImage:"CompanyRMM.exe",severities:["High","Critical"],risk:[75,96],tags:["defense-evasion","tampering"],behavior:"security-control tampering",followOn:"Security telemetry gap begins",command:()=>"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true; wevtutil cl Security",benignCommand:c=>`CompanyRMM.exe /maintenance /ticket CHG-${int(c.rng,10000,99999)}`})
);

function makeNetworkScenario(spec){
  return {
    key:spec.key,ruleId:spec.ruleId,product:"Network Detection & Response",dataSource:spec.dataSource,mitre:spec.mitre,technique:spec.technique,
    build(c){
      const benign=chance(c.rng,spec.benignChance),destination=externalIp(c.rng),sourceIp=c.host.ip,interval=int(c.rng,spec.interval[0],spec.interval[1]),events=int(c.rng,spec.events[0],spec.events[1]),bytes=int(c.rng,spec.bytes[0],spec.bytes[1]);
      const severity=benign?"Low":pick(c.rng,spec.severities),risk=benign?int(c.rng,10,29):int(c.rng,spec.risk[0],spec.risk[1]),intel=makeIntel(c,destination,benign?int(c.rng,0,14):int(c.rng,62,96),benign?"Benign":"Suspicious",benign?["approved-service"]:spec.tags,benign);
      const process=benign?pick(c.rng,spec.benignProcesses):pick(c.rng,spec.processes),port=pick(c.rng,spec.ports);
      return {name:benign?spec.benignName:pick(c.rng,spec.variants),severity,riskScore:risk,confidence:benign?"High":"Medium",complexity:benign?"Low":"High",sourceIp,intel,eventCount:events,logCompleteness:pick(c.rng,["74%","82%","91%"]),
        summary:benign?`${c.host.hostname} contacted an approved ${spec.service} endpoint every ${interval} seconds; process signer and destination are allowlisted.`:`${c.host.hostname} generated ${events} ${spec.service} events at a ${interval}-second interval to rare destination ${destination}.`,
        overview:[{label:"Event count",value:String(events)},{label:"Interval",value:`${interval} seconds`,tone:benign?"good":"danger"},{label:"Bytes transferred",value:`${bytes} KB`},{label:"Owning process",value:process},{label:"Destination",value:destination},{label:"Internal prevalence",value:intel.internalPrevalence}],
        timeline:[timeline(c,-interval*3,`${spec.service} pattern begins`,spec.dataSource,`${events} events correlated`),timeline(c,-interval*2,`Process attribution: ${process}`,"EDR","Socket owner resolved"),timeline(c,-interval,`Destination enriched as ${intel.verdict}`,"Threat Intel",`Score ${intel.score}/100`),timeline(c,0,"Network analytic raised","NDR",`Risk ${risk}/100`)],
        process:[proc(process,int(c.rng,1800,14000),pick(c.rng,["services.exe","explorer.exe","unknown"]),`${process} ${benign?"--telemetry":"--background"}`,benign?"Valid":"Unknown",benign?"Approved":"Suspicious")],
        network:[netRow(c,-interval*3,c.host.ip,destination,port,spec.protocol,"Outbound",`${bytes} KB`,benign?"Allowlisted service":`${events} events / ${interval}s periodicity`)],
        auth:[authRow(c,-1200,"4624","Interactive","Success",c.host.ip,c.host.hostname,"N/A")],
        scope:[scopeRow(c.host.hostname,"Endpoint",events,timeAt(c,-interval),benign?"Expected traffic":"Possible C2"),scopeRow(destination,"Destination",events,timeAt(c,-interval),intel.verdict),scopeRow(process,"Process",1,timeAt(c,-interval*2),benign?"Signed":"Needs validation")],
        rawLogs:[`flow src=${c.host.ip} dest=${destination} port=${port} protocol=${spec.protocol} count=${events} interval_sec=${interval} bytes=${bytes*1024}`,`process=${process} host=${c.host.hostname} destination_reputation=${intel.verdict} prevalence="${intel.internalPrevalence}"`],
        expected:benign?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("Needs More Investigation",severity,"Request More Logs / Enrichment","Suspicious","Inconclusive","Inconclusive")};
    }
  };
}

SCENARIOS.push(
  makeNetworkScenario({key:"beaconing",ruleId:"NDR-7002",dataSource:"Firewall / EDR",mitre:"Command and Control",technique:"T1071.001 Web Protocols",service:"TLS beacon",protocol:"TLS",ports:[443,8443,8080],interval:[30,180],events:[24,340],bytes:[120,2400],benignChance:.2,severities:["High","Medium"],risk:[62,91],tags:["c2","periodic"],processes:["svchost.exe","update-check.exe","unknown.exe"],benignProcesses:["Teams.exe","OneDrive.exe","CorpAgent.exe"],variants:["Periodic TLS Beacon to Rare Destination","Low-Volume C2-Like Network Pattern","Rare Destination With Stable Beacon Interval"],benignName:"Approved Application Telemetry Beacon"}),
  makeNetworkScenario({key:"dns_tunnel",ruleId:"DNS-7205",dataSource:"DNS / Firewall",mitre:"Exfiltration",technique:"T1048.003 Exfiltration Over Unencrypted Protocol",service:"DNS query",protocol:"DNS",ports:[53],interval:[1,12],events:[90,980],bytes:[50,7600],benignChance:.16,severities:["High","Critical"],risk:[70,95],tags:["dns-tunnel","exfiltration"],processes:["powershell.exe","dnsclient.exe","unknown.exe"],benignProcesses:["backup-agent.exe","inventory-agent.exe"],variants:["High-Entropy DNS Queries Suggest Tunneling","Unusual TXT Query Volume From Endpoint","Possible DNS Data Exfiltration"],benignName:"Approved Inventory Agent DNS Burst"})
);

function makeAccessScenario(spec){
  return {
    key:spec.key,ruleId:spec.ruleId,product:"Microsoft Sentinel",dataSource:"Windows Security",mitre:spec.mitre,technique:spec.technique,
    build(c){
      const authorized=chance(c.rng,spec.authorizedChance),sourceIp=internalIp(c.rng),events=int(c.rng,2,29),ticket=authorized?`CHG-${int(c.rng,10000,99999)}`:"No ticket",severity=authorized?"Low":pick(c.rng,spec.severities),risk=authorized?int(c.rng,9,26):int(c.rng,spec.risk[0],spec.risk[1]);
      const intel=makeIntel(c,sourceIp,authorized?0:int(c.rng,20,48),authorized?"Benign":"Unknown",authorized?["admin-jump-host"]:["internal-source"],authorized);
      return {name:authorized?spec.authorizedName:pick(c.rng,spec.variants),severity,riskScore:risk,confidence:authorized?"High":"High",complexity:authorized?"Low":"High",sourceIp,intel,eventCount:events,logCompleteness:"100%",
        summary:authorized?`${spec.activity} on ${c.host.hostname} matches ${ticket}, an approved admin account and the maintenance window.`:`${spec.activity} was observed on ${c.host.hostname} from ${sourceIp} with no approved change record.`,
        overview:[{label:"Security event",value:spec.eventId},{label:"Source host",value:sourceIp},{label:"Target",value:c.host.hostname},{label:"Account",value:c.user.username},{label:"Change ticket",value:ticket,tone:authorized?"good":"danger"},{label:"Privilege",value:c.user.privilege}],
        timeline:[timeline(c,-240,`Network logon from ${sourceIp}`,"Windows Security","Event 4624"),timeline(c,-119,spec.activity,"Windows Security",`Event ${spec.eventId}`),timeline(c,-61,spec.followOn,"EDR",authorized?"Expected admin activity":"Unusual follow-on"),timeline(c,0,"Correlation rule raised","SIEM",`Risk ${risk}/100`)],
        process:[proc(spec.process,int(c.rng,3500,12000),pick(c.rng,["services.exe","cmd.exe","wsmprovhost.exe"]),spec.command(c),authorized?"Valid":"Valid",authorized?"Approved":"Suspicious")],
        network:[netRow(c,-240,sourceIp,c.host.ip,pick(c.rng,spec.ports),"TCP","Internal",`${int(c.rng,1,24)} MB`,authorized?"Known admin path":"Unusual east-west access")],
        auth:[authRow(c,-240,"4624","Network","Success",sourceIp,c.host.hostname,"N/A"),authRow(c,-119,spec.eventId,spec.activity,"Observed",sourceIp,c.host.hostname,"N/A")],
        scope:[scopeRow(c.host.hostname,"Target endpoint",events,timeAt(c,-61),authorized?"Approved change":"Affected"),scopeRow(c.user.username,"Identity",events,timeAt(c,-119),authorized?"Authorized admin":"Unexpected privilege use"),scopeRow(sourceIp,"Internal source",events,timeAt(c,-61),authorized?"Admin jump host":"Requires scoping")],
        rawLogs:[`EventID=4624 TargetUser=${c.user.username} IpAddress=${sourceIp} Workstation=${c.host.hostname} LogonType=3`,`EventID=${spec.eventId} Target=${c.host.hostname} SubjectUser=${c.user.username} ChangeTicket="${ticket}"`,`process=${spec.process} command="${spec.command(c)}"`],
        expected:authorized?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("True Positive",severity,"Escalate to L2 / Incident Response","Inconclusive","Confirmed","Confirmed")};
    }
  };
}

SCENARIOS.push(
  makeAccessScenario({key:"privilege_escalation",ruleId:"WIN-4732",mitre:"Privilege Escalation",technique:"T1098 Account Manipulation",authorizedChance:.2,severities:["High","Critical"],risk:[74,96],eventId:"4732",activity:"Account added to local Administrators group",followOn:"Special privileges assigned",process:"net.exe",ports:[445,5985],variants:["Unauthorized Account Added to Administrators","Service Account Granted Local Admin Rights","Privileged Group Membership Changed Outside Window"],authorizedName:"Approved Administrator Group Change",command:c=>`net.exe localgroup administrators ${c.user.username} /add`}),
  makeAccessScenario({key:"lateral_movement",ruleId:"WIN-7045",mitre:"Lateral Movement",technique:"T1021.002 SMB / Windows Admin Shares",authorizedChance:.17,severities:["High","Critical"],risk:[78,97],eventId:"7045",activity:"Remote service created after admin-share access",followOn:"Service binary executed remotely",process:"sc.exe",ports:[445,5985,3389],variants:["Remote Service Creation From Unfamiliar Host","Possible PsExec Lateral Movement","Admin Share Access Followed by Service Install"],authorizedName:"Approved Remote Software Deployment",command:c=>`sc.exe \\\\${c.host.hostname} create UpdateSvc binPath= C:\\Windows\\Temp\\svc-${int(c.rng,10,99)}.exe`})
);

SCENARIOS.push({
  key:"web_shell",ruleId:"WEB-8103",product:"WAF + EDR",dataSource:"Web / EDR",mitre:"Persistence",technique:"T1505.003 Web Shell",
  build(c){
    c.host={...pick(c.rng,ASSETS.filter(a=>a.hostname.startsWith("SRV-")))};c.user={...IDENTITIES.find(u=>u.username==="websvc")};
    const sourceIp=externalIp(c.rng),shell=pick(c.rng,["healthcheck.aspx","upload.php","error-handler.jsp"]),requests=int(c.rng,3,42),dest=externalIp(c.rng),hash=fakeHash(c.rng),severity="Critical",risk=int(c.rng,89,99),intel=makeIntel(c,sourceIp,int(c.rng,77,99),"Malicious",["web-exploit","web-shell"]);
    return {name:`Web Shell Activity: ${shell}`,severity,riskScore:risk,confidence:"High",complexity:"High",sourceIp,intel,eventCount:requests+5,logCompleteness:pick(c.rng,["86%","93%","100%"]),summary:`${requests} requests from ${sourceIp} were followed by ${shell} creation and command execution under ${c.user.username} on ${c.host.hostname}.`,overview:[{label:"Web shell",value:shell,tone:"danger"},{label:"HTTP requests",value:String(requests)},{label:"Process owner",value:c.user.username},{label:"File hash",value:hash.slice(0,18)+"…"},{label:"Outbound target",value:dest},{label:"Asset criticality",value:c.host.criticality}],timeline:[timeline(c,-360,"Exploit-like POST request","WAF",`Source ${sourceIp}`),timeline(c,-211,`${shell} created in web root`,"File integrity","New executable content"),timeline(c,-122,"Command shell spawned by web worker","EDR","Process anomaly"),timeline(c,-49,`Outbound connection to ${dest}`,"Firewall","Rare destination"),timeline(c,0,"Web-shell correlation raised","SIEM",`Risk ${risk}/100`)],process:[proc("w3wp.exe",int(c.rng,1100,4500),"services.exe","w3wp.exe -ap AppPool","Microsoft signed","Expected"),proc("cmd.exe",int(c.rng,4501,9000),"w3wp.exe","cmd.exe /c whoami & ipconfig","Microsoft signed","Malicious",hash)],network:[netRow(c,-360,sourceIp,c.host.ip,443,"HTTPS","Inbound",`${int(c.rng,30,900)} KB`,"Exploit-like POST"),netRow(c,-49,c.host.ip,dest,443,"TLS","Outbound",`${int(c.rng,90,1200)} KB`,"Rare / malicious")],auth:[authRow(c,-211,"IIS","Application pool","Success",sourceIp,c.host.hostname,"N/A")],scope:[scopeRow(c.host.hostname,"Web server",requests,timeAt(c,-49),"Confirmed affected"),scopeRow(shell,"File",1,timeAt(c,-211),"Malicious web shell"),scopeRow(sourceIp,"Source IP",requests,timeAt(c,-360),"Malicious")],rawLogs:[`waf src=${sourceIp} host=${c.host.hostname} method=POST uri=/${shell} requests=${requests}`,`file_create path=C:\\inetpub\\wwwroot\\${shell} sha256=${hash} user=${c.user.username}`,`process parent=w3wp.exe child=cmd.exe command="whoami & ipconfig"`],expected:expected("True Positive","Critical","Contain Host and Escalate","Suspicious","Confirmed","Confirmed")};
  }
});

SCENARIOS.push({
  key:"oauth_consent",ruleId:"CLOUD-8406",product:"Microsoft Entra ID",dataSource:"Cloud Audit",mitre:"Persistence",technique:"T1098.003 Additional Cloud Roles",
  build(c){
    const verified=chance(c.rng,.28),app=verified?pick(c.rng,["Adobe Sign","ServiceNow","Microsoft Graph Explorer"]):`DocSync-${int(c.rng,100,9999)}`,scopes=verified?["User.Read"]:pick(c.rng,[["Mail.ReadWrite","offline_access"],["Files.Read.All","User.Read"],["Directory.ReadWrite.All"]]),sourceIp=externalIp(c.rng),severity=verified?"Low":"High",risk=verified?int(c.rng,8,24):int(c.rng,72,94),intel=makeIntel(c,sourceIp,verified?int(c.rng,0,12):int(c.rng,45,78),verified?"Benign":"Suspicious",verified?["verified-publisher"]:["unverified-app"],verified);
    return {name:verified?"Verified OAuth Application Consent":`High-Risk OAuth Consent: ${app}`,severity,riskScore:risk,confidence:verified?"High":"Medium",complexity:verified?"Low":"High",sourceIp,intel,eventCount:int(c.rng,2,9),logCompleteness:"100%",summary:`${c.user.username} granted ${Array.isArray(scopes)?scopes.join(", "):scopes} to ${app}. ${verified?"Publisher verification and approved catalog entry are present.":"The publisher is unverified and requested permissions exceed the user's baseline."}`,overview:[{label:"Application",value:app},{label:"Publisher",value:verified?"Verified":"Unverified",tone:verified?"good":"danger"},{label:"Permissions",value:Array.isArray(scopes)?scopes.join(", "):scopes},{label:"Consent type",value:"User consent"},{label:"Source IP",value:sourceIp},{label:"Prior tenant use",value:verified?"Common":"Never seen"}],timeline:[timeline(c,-190,"Interactive cloud sign-in","Entra ID","User session"),timeline(c,-71,`Consent granted to ${app}`,"Cloud Audit",Array.isArray(scopes)?scopes.join(", "):scopes),timeline(c,-34,"Refresh token issued","Entra ID",verified?"Expected":"Persistent access"),timeline(c,0,"Risky-consent rule raised","SIEM",`Risk ${risk}/100`)],process:[proc("Cloud application","—","—",app,verified?"Verified publisher":"Unverified","Identity-only")],network:[netRow(c,-190,sourceIp,"login.microsoftonline.com",443,"HTTPS","Inbound","96 KB",verified?"Expected sign-in":"Unfamiliar source")],auth:[authRow(c,-190,"EntraSignIn","Interactive","Success",sourceIp,c.host.hostname,"Satisfied")],scope:[scopeRow(c.user.username,"Identity",1,timeAt(c,-71),verified?"Approved consent":"Token exposure"),scopeRow(app,"OAuth application",1,timeAt(c,-34),verified?"Approved catalog":"Unverified"),scopeRow(Array.isArray(scopes)?scopes.join(", "):scopes,"Permissions",1,timeAt(c,-71),verified?"Low impact":"High impact")],rawLogs:[`operation=ConsentToApplication user=${c.user.username} app=${app} publisher_verified=${verified}`,`scopes="${Array.isArray(scopes)?scopes.join(" "):scopes}" source_ip=${sourceIp} refresh_token_issued=true`],expected:verified?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("True Positive","High","Disable Account and Escalate","Suspicious","Inconclusive","Confirmed")};
  }
});

SCENARIOS.push({
  key:"usb_exfil",ruleId:"DLP-9004",product:"Endpoint DLP",dataSource:"DLP / USB",mitre:"Exfiltration",technique:"T1052.001 Exfiltration over USB",
  build(c){
    const approved=chance(c.rng,.25),files=int(c.rng,18,2800),gb=(int(c.rng,12,920)/10).toFixed(1),device=approved?"CORP-BACKUP-USB":`USB-${fakeHash(c.rng,8).toUpperCase()}`,sourceIp=c.host.ip,severity=approved?"Low":files>800?"High":"Medium",risk=approved?int(c.rng,10,26):int(c.rng,58,91),intel=makeIntel(c,device,approved?0:45,approved?"Benign":"Unknown",approved?["approved-encrypted-media"]:["removable-media"],approved);
    return {name:approved?"Approved Encrypted USB Backup":`Sensitive File Copy to Unmanaged USB (${gb} GB)`,severity,riskScore:risk,confidence:"High",complexity:approved?"Low":"Medium",sourceIp,intel,eventCount:files,logCompleteness:"100%",summary:`${c.user.username} copied ${files} files (${gb} GB) from ${c.host.hostname} to ${device}. ${approved?"The encrypted device and DLP exception are approved.":"The device is unmanaged and no business justification is recorded."}`,overview:[{label:"Files copied",value:String(files),tone:approved?"good":"danger"},{label:"Data volume",value:`${gb} GB`},{label:"USB device",value:device},{label:"Encryption",value:approved?"Corporate encrypted":"Unknown"},{label:"DLP exception",value:approved?`DLP-${int(c.rng,1000,9999)}`:"None"},{label:"Data labels",value:pick(c.rng,["Confidential","Finance","PII"])}],timeline:[timeline(c,-720,"USB device mounted","Endpoint DLP",device),timeline(c,-511,"Sensitive file-copy burst begins","DLP",`${files} files`),timeline(c,-92,"Copy completes","DLP",`${gb} GB transferred`),timeline(c,0,"DLP threshold alert raised","SIEM",`Risk ${risk}/100`)],process:[proc("explorer.exe",int(c.rng,1200,6000),"userinit.exe",`copy C:\\Sensitive\\* ${pick(c.rng,["E:","F:"])}\\`,"Microsoft signed",approved?"Approved":"Policy violation")],network:[],auth:[authRow(c,-900,"4624","Interactive","Success",c.host.ip,c.host.hostname,"N/A")],scope:[scopeRow(c.host.hostname,"Endpoint",files,timeAt(c,-92),approved?"Approved transfer":"Source affected"),scopeRow(c.user.username,"Identity",files,timeAt(c,-92),approved?"Authorized":"Requires manager validation"),scopeRow(device,"USB device",files,timeAt(c,-92),approved?"Managed":"Unmanaged")],rawLogs:[`dlp action=file_copy user=${c.user.username} host=${c.host.hostname} device=${device} files=${files} bytes_gb=${gb}`,`device_encrypted=${approved} exception=${approved?"valid":"none"} labels=confidential`],expected:approved?expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed"):expected("True Positive",severity,"Escalate to L2 / Incident Response","Inconclusive","Confirmed","Confirmed")};
  }
});

SCENARIOS.push({
  key:"approved_scanner",ruleId:"NET-9501",product:"Microsoft Sentinel",dataSource:"Firewall / IDS",mitre:"Discovery",technique:"T1046 Network Service Scanning",
  build(c){
    c.user={...IDENTITIES.find(u=>u.username==="svc_scanner")};const sourceIp="10.20.5.10",ports=int(c.rng,800,65535),targets=int(c.rng,12,240),risk=int(c.rng,5,19),intel=makeIntel(c,sourceIp,0,"Benign",["approved-scanner","internal"],true);
    return {name:`Approved Vulnerability Scan: ${targets} targets`,severity:"Low",riskScore:risk,confidence:"High",complexity:"Low",sourceIp,intel,eventCount:ports,logCompleteness:"100%",summary:`Registered scanner ${sourceIp} probed ${ports} ports across ${targets} assets during approved window VULN-${int(c.rng,1000,9999)}. No exploitation followed.`,overview:[{label:"Source",value:sourceIp},{label:"Ports probed",value:String(ports)},{label:"Targets",value:String(targets)},{label:"Scanner owner",value:"Security Engineering"},{label:"Change window",value:"Approved",tone:"good"},{label:"Follow-on exploit",value:"None",tone:"good"}],timeline:[timeline(c,-1800,"Approved scan window opens","Change Management","Scanner allowlisted"),timeline(c,-900,"Port sweep crosses IDS threshold","Firewall",`${targets} targets`),timeline(c,-120,"Scan completes","Scanner","No exploit findings"),timeline(c,0,"Volume rule creates alert","SIEM",`Risk ${risk}/100`)],process:[proc("scanner-agent.exe",int(c.rng,1000,5000),"systemd","scanner-agent --scheduled","Vendor signed","Approved")],network:[netRow(c,-900,sourceIp,"10.0.0.0/8","1-65535","TCP","Internal","N/A",`Approved scan of ${targets} targets`)],auth:[authRow(c,-1800,"ServiceLogon","Service","Success",sourceIp,"SCAN-01","N/A")],scope:[scopeRow(sourceIp,"Known scanner",ports,timeAt(c,-120),"Allowlisted"),scopeRow(`${targets} assets`,"Targets",targets,timeAt(c,-120),"Scanned only")],rawLogs:[`ids signature=port_scan src=${sourceIp} targets=${targets} ports=${ports}`,`asset_registry ip=${sourceIp} owner=security role=vulnerability_scanner approved=true`,`change window=approved exploit_follow_on=false`],expected:expected("False Positive","Low","Close as False Positive","Benign","Not affected","Not confirmed")};
  }
});

function createGeneratedAlert(index,datasetSeed,forcedScenarioIndex){
  const scenarioIndex=Number.isInteger(forcedScenarioIndex)?forcedScenarioIndex:index%SCENARIOS.length;
  const scenario=SCENARIOS[scenarioIndex],c=buildContext(index,datasetSeed,scenarioIndex),result=scenario.build(c);
  return {
    schemaVersion:STORAGE_VERSION,
    id:`ALT-${String(index+1).padStart(5,"0")}`,
    detectedAt:c.detectedAt,
    time:formatDateTime(c.detectedAt),
    name:result.name,
    severity:result.severity,
    riskScore:result.riskScore,
    confidence:result.confidence,
    complexity:result.complexity,
    host:c.host.hostname,
    user:c.user.username,
    ip:result.sourceIp,
    asset:c.host,
    identity:c.user,
    status:"New",
    owner:"Unassigned",
    mitre:scenario.mitre,
    technique:scenario.technique,
    scenarioKey:scenario.key,
    scenarioIndex,
    ruleId:scenario.ruleId,
    product:scenario.product,
    dataSource:scenario.dataSource,
    eventCount:result.eventCount,
    logCompleteness:result.logCompleteness,
    summary:result.summary,
    evidence:{overview:result.overview||[],timeline:result.timeline||[],process:result.process||[],network:result.network||[],auth:result.auth||[],intel:result.intel,scope:result.scope||[],raw:result.rawLogs||[]},
    expected:result.expected,
    custom:false,
    note:"",
    decision:null,
    progress:{visitedTabs:[],openedAt:null,lastViewedAt:null}
  };
}

function scenarioIndexFromLegacy(alert){
  const name=String(alert?.name||"").toLowerCase();
  if(name.includes("brute"))return 0;if(name.includes("impossible"))return 1;if(name.includes("powershell"))return 2;if(name.includes("phish"))return 3;
  if(name.includes("scheduled"))return SCENARIOS.findIndex(s=>s.key==="scheduled_task");if(name.includes("beacon"))return SCENARIOS.findIndex(s=>s.key==="beaconing");
  if(name.includes("privilege"))return SCENARIOS.findIndex(s=>s.key==="privilege_escalation");if(name.includes("scanner"))return SCENARIOS.findIndex(s=>s.key==="approved_scanner");return 0;
}

function normalizeAlert(alert,index=0,datasetSeed=state.datasetSeed){
  if(alert&&Number(alert.schemaVersion)===STORAGE_VERSION&&alert.evidence&&alert.expected){
    const copy={...alert};
    copy.severity=["Critical","High","Medium","Low"].includes(copy.severity)?copy.severity:"Medium";
    copy.status=["New","In Progress","Escalated","Closed"].includes(copy.status)?copy.status:"New";
    copy.riskScore=Math.max(0,Math.min(100,Number(copy.riskScore)||0));
    copy.progress=copy.progress&&typeof copy.progress==="object"?copy.progress:{visitedTabs:[]};
    copy.progress.visitedTabs=Array.isArray(copy.progress.visitedTabs)?copy.progress.visitedTabs:[];
    copy.note=String(copy.note||"");copy.owner=String(copy.owner||"Unassigned");
    return copy;
  }
  const scenarioIndex=Math.max(0,scenarioIndexFromLegacy(alert)),fresh=createGeneratedAlert(index,datasetSeed,scenarioIndex);
  fresh.id=String(alert?.id||fresh.id);fresh.status=["New","In Progress","Escalated","Closed"].includes(alert?.status)?alert.status:"New";fresh.owner=String(alert?.owner||"Unassigned");fresh.note=String(alert?.note||"");fresh.decision=alert?.decision&&typeof alert.decision==="object"?{...alert.decision,scoreMax:Number(alert.decision.scoreMax)||3}:null;fresh.custom=Boolean(alert?.custom);
  if(fresh.custom){fresh.name=String(alert?.name||fresh.name);fresh.severity=["Critical","High","Medium","Low"].includes(alert?.severity)?alert.severity:fresh.severity;fresh.host=String(alert?.host||fresh.host);fresh.user=String(alert?.user||fresh.user);fresh.ip=String(alert?.ip||fresh.ip);fresh.summary=String(alert?.summary||fresh.summary)}
  return fresh;
}

function setSaveLabel(text,ok=true){
  [document.getElementById("saveState"),document.getElementById("saveStateSide")].forEach(el=>{if(!el)return;el.textContent=(ok?"● ":"⚠ ")+text;el.classList.toggle("good",ok);el.classList.toggle("warn",!ok)});
}

function saveState(){
  const payload={version:STORAGE_VERSION,savedAt:new Date().toISOString(),datasetSeed:state.datasetSeed,alerts:state.alerts};
  try{localStorage.setItem(STORAGE_KEY,JSON.stringify(payload));state.storageAvailable=true;setSaveLabel("Saved locally",true)}
  catch(err){state.storageAvailable=false;setSaveLabel("Storage full — export progress",false);console.warn("Local storage unavailable",err)}
}

function loadState(){
  try{
    const current=localStorage.getItem(STORAGE_KEY),legacy=!current?localStorage.getItem(LEGACY_STORAGE_KEY):null,raw=current||legacy;if(!raw)return false;
    const data=JSON.parse(raw);if(!data||!Array.isArray(data.alerts)||!data.alerts.length)return false;
    state.datasetSeed=Number(data.datasetSeed)||Date.now();state.alerts=data.alerts.map((a,i)=>normalizeAlert(a,i,state.datasetSeed));state.storageAvailable=true;
    if(legacy){saveState();setSaveLabel("v2 progress upgraded",true)}else setSaveLabel("Progress restored",true);
    return true;
  }catch(err){console.warn("Could not restore saved state",err);return false}
}

function generateAlerts(count=DATASET_SIZE){
  state.datasetSeed=Date.now();state.alerts=Array.from({length:count},(_,i)=>createGeneratedAlert(i,state.datasetSeed));
  state.alerts.sort((a,b)=>String(b.detectedAt).localeCompare(String(a.detectedAt)));state.page=1;saveState();renderAll();
}

function investigatedAlerts(){return state.alerts.filter(a=>a.decision)}
function escalatedAlerts(){return state.alerts.filter(a=>a.status==="Escalated")}
function accuracy(){const done=investigatedAlerts();if(!done.length)return null;return Math.round(done.filter(a=>Number(a.decision?.score)===Number(a.decision?.scoreMax||MAX_SCORE)).length/done.length*100)}

function getFiltered(){
  const q=document.getElementById("searchInput").value.trim().toLowerCase(),severity=document.getElementById("severityFilter").value,status=document.getElementById("statusFilter").value,complexity=document.getElementById("complexityFilter").value;
  return state.alerts.filter(a=>{const hay=[a.id,a.name,a.host,a.user,a.ip,a.ruleId,a.technique,a.dataSource,a.complexity].join(" ").toLowerCase();return(!q||hay.includes(q))&&(!severity||a.severity===severity)&&(!status||a.status===status)&&(!complexity||a.complexity===complexity)});
}

function renderKPIs(){
  const open=state.alerts.filter(a=>a.status!=="Closed"),critical=open.filter(a=>a.severity==="Critical").length,average=open.length?Math.round(open.reduce((sum,a)=>sum+a.riskScore,0)/open.length):0,acc=accuracy();
  document.getElementById("kpiOpen").textContent=open.length;document.getElementById("kpiCritical").textContent=critical;document.getElementById("kpiInvestigated").textContent=investigatedAlerts().length;document.getElementById("kpiEscalated").textContent=escalatedAlerts().length;document.getElementById("kpiAccuracy").textContent=acc===null?"—":`${acc}%`;document.getElementById("kpiRisk").textContent=average;
}

function renderSeverity(){
  const counts={Critical:0,High:0,Medium:0,Low:0};state.alerts.filter(a=>a.status!=="Closed").forEach(a=>counts[a.severity]++);const total=Object.values(counts).reduce((a,b)=>a+b,0)||1,p1=counts.Critical/total*100,p2=counts.High/total*100,p3=counts.Medium/total*100;
  document.getElementById("donutTotal").textContent=total;document.getElementById("severityDonut").style.background=`conic-gradient(var(--red) 0 ${p1}%, var(--orange) ${p1}% ${p1+p2}%, var(--yellow) ${p1+p2}% ${p1+p2+p3}%, var(--green) ${p1+p2+p3}% 100%)`;document.getElementById("severityLegend").innerHTML=Object.entries(counts).map(([key,value])=>`<div class="legend-row">${sevDot(key)}<span>${key}</span><strong>${value}</strong></div>`).join("");
}

function renderChart(){
  const canvas=document.getElementById("alertsChart"),ctx=canvas.getContext("2d"),data=Array(24).fill(0),now=Date.now();
  state.alerts.forEach(a=>{const age=Math.floor((now-new Date(a.detectedAt).getTime())/3600000);if(age>=0&&age<24)data[23-age]++});
  const max=Math.max(...data,1),scale=170/max;ctx.clearRect(0,0,canvas.width,canvas.height);ctx.strokeStyle="#20364f";ctx.lineWidth=1;
  for(let y=30;y<230;y+=50){ctx.beginPath();ctx.moveTo(42,y);ctx.lineTo(740,y);ctx.stroke()}
  ctx.fillStyle="rgba(45,140,255,.12)";ctx.beginPath();data.forEach((value,i)=>{const x=45+i*(690/23),y=215-value*scale;if(i===0){ctx.moveTo(x,215);ctx.lineTo(x,y)}else ctx.lineTo(x,y)});ctx.lineTo(735,215);ctx.closePath();ctx.fill();
  ctx.strokeStyle="#2d8cff";ctx.lineWidth=3;ctx.beginPath();data.forEach((value,i)=>{const x=45+i*(690/23),y=215-value*scale;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y)});ctx.stroke();ctx.fillStyle="#94a8bd";ctx.font="11px system-ui";[[0,"24h ago"],[6,"18h"],[12,"12h"],[18,"6h"],[23,"Now"]].forEach(([i,label])=>ctx.fillText(label,40+i*(690/23),248));
}

function progressMark(a){return a.decision?`<span class="investigated-mark">✓ Investigated ${a.decision.score}/${a.decision.scoreMax||MAX_SCORE}</span>`:a.status==="In Progress"?'<span class="muted-mark">In progress</span>':'<span class="muted-mark">Not started</span>'}

function renderTelemetryHealth(){
  const sources=[...new Set(state.alerts.map(a=>a.dataSource))].slice(0,6);document.getElementById("telemetryHealth").innerHTML=sources.map(source=>{const latency=hashString(source)%9+1,status=latency>7?"Degraded":"Healthy",count=state.alerts.filter(a=>a.dataSource===source).length;return `<div><span><strong>${escapeHTML(source)}</strong><small>${count} alerts • ${latency}m latency</small></span><b class="${status==="Healthy"?"ok":"warn"}">${status}</b></div>`}).join("");
}

function renderRecent(){
  const rows=state.alerts.filter(a=>["Critical","High"].includes(a.severity)&&a.status!=="Closed").slice(0,8);document.getElementById("recentTable").innerHTML=rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.time.slice(11))}</td><td>${escapeHTML(a.name)}</td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td>${escapeHTML(a.host)}</td><td>${progressMark(a)}</td></tr>`).join("");document.querySelectorAll("#recentTable tr").forEach(row=>row.addEventListener("click",()=>openInvestigation(row.dataset.id)));
}

function renderMitre(){
  const counts={};state.alerts.forEach(a=>counts[a.mitre]=(counts[a.mitre]||0)+1);const max=Math.max(...Object.values(counts),1);document.getElementById("mitreCoverage").innerHTML=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,7).map(([name,count])=>{const percent=Math.round(count/max*100);return `<div class="cov-row"><span>${escapeHTML(name)}</span><div class="bar"><span style="width:${percent}%"></span></div><b>${count}</b></div>`}).join("");
}

function renderAlerts(){
  const filtered=getFiltered();document.getElementById("alertCountText").textContent=filtered.length;const maxPage=Math.max(1,Math.ceil(filtered.length/state.pageSize));if(state.page>maxPage)state.page=maxPage;const start=(state.page-1)*state.pageSize,rows=filtered.slice(start,start+state.pageSize);
  document.getElementById("alertsTable").innerHTML=rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.time)}</td><td><strong>${escapeHTML(a.name)}</strong>${a.custom?' <span class="badge">Custom</span>':''}<small class="subline">${escapeHTML(a.technique)}</small></td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td><span class="risk-pill ${riskClass(a.riskScore)}">${a.riskScore}</span></td><td>${escapeHTML(a.complexity)}</td><td>${escapeHTML(a.host)}</td><td>${escapeHTML(a.user)}</td><td>${escapeHTML(a.ip)}</td><td>${escapeHTML(a.ruleId)}</td><td><span class="badge">${escapeHTML(a.status)}</span></td><td>${progressMark(a)}</td></tr>`).join("");
  document.querySelectorAll("#alertsTable tr").forEach(row=>row.addEventListener("click",()=>openInvestigation(row.dataset.id)));document.getElementById("pageInfo").textContent=`Page ${state.page} of ${maxPage}`;document.getElementById("prevPage").disabled=state.page<=1;document.getElementById("nextPage").disabled=state.page>=maxPage;
}

function renderIncidents(){
  const rows=escalatedAlerts();document.getElementById("incidentsTable").innerHTML=rows.length?rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.name)}</td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td>${escapeHTML(a.host)}</td><td>${escapeHTML(a.user)}</td><td>${escapeHTML(a.owner)}</td><td>${escapeHTML(a.decision?.submittedAt||"")}</td></tr>`).join(""):'<tr><td colspan="7">No escalated incidents yet.</td></tr>';document.querySelectorAll("#incidentsTable tr[data-id]").forEach(row=>row.addEventListener("click",()=>openInvestigation(row.dataset.id)));
}

function renderHistory(){
  const rows=investigatedAlerts().sort((a,b)=>String(b.decision?.submittedAtISO||"").localeCompare(String(a.decision?.submittedAtISO||"")));document.getElementById("historyTable").innerHTML=rows.length?rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.name)}</td><td>${escapeHTML(a.decision.classification)}</td><td>${escapeHTML(a.decision.severity)}</td><td>${escapeHTML(a.decision.action)}</td><td>${escapeHTML(a.decision.score)}/${escapeHTML(a.decision.scoreMax||MAX_SCORE)}</td><td>${escapeHTML(a.decision.submittedAt)}</td></tr>`).join(""):'<tr><td colspan="7">No investigations completed yet.</td></tr>';document.querySelectorAll("#historyTable tr[data-id]").forEach(row=>row.addEventListener("click",()=>openInvestigation(row.dataset.id)));
}

function renderAssets(){
  const grouped={};state.alerts.forEach(a=>{const item=grouped[a.host]||(grouped[a.host]={asset:a.asset,alerts:0,open:0,critical:0,risk:0,last:a.detectedAt});item.alerts++;item.risk+=a.riskScore;if(a.status!=="Closed")item.open++;if(a.severity==="Critical")item.critical++;if(a.detectedAt>item.last)item.last=a.detectedAt});
  const top=Object.values(grouped).sort((a,b)=>b.risk-a.risk).slice(0,16);document.getElementById("assetsGrid").innerHTML=top.map((item,i)=>`<button class="asset" data-host="${escapeHTML(item.asset.hostname)}"><span>#${i+1} accumulated risk</span><strong>${escapeHTML(item.asset.hostname)}</strong><div class="asset-risk"><b>${item.open}</b> open • <b>${item.critical}</b> critical • avg risk <b>${Math.round(item.risk/item.alerts)}</b></div><p>${escapeHTML(item.asset.criticality)} criticality • ${escapeHTML(item.asset.os)}</p><p>EDR: ${escapeHTML(item.asset.edrStatus)} • ${escapeHTML(item.asset.department)}</p></button>`).join("");
  document.querySelectorAll("#assetsGrid [data-host]").forEach(button=>button.addEventListener("click",()=>{document.getElementById("searchInput").value=button.dataset.host;state.page=1;switchView("alerts")}));
}

function renderDetections(){
  const rules={};state.alerts.forEach(a=>{const item=rules[a.ruleId]||(rules[a.ruleId]={ruleId:a.ruleId,name:a.name,source:a.dataSource,mitre:a.mitre,alerts:0,investigated:0,full:0});item.alerts++;if(a.decision)item.investigated++;if(a.decision&&Number(a.decision.score)===Number(a.decision.scoreMax||MAX_SCORE))item.full++});
  document.getElementById("detectionRulesTable").innerHTML=Object.values(rules).sort((a,b)=>b.alerts-a.alerts).map(item=>`<tr><td><strong>${escapeHTML(item.ruleId)}</strong></td><td>${escapeHTML(item.name)}</td><td>${escapeHTML(item.source)}</td><td>${escapeHTML(item.mitre)}</td><td>${item.alerts}</td><td>${item.investigated}</td><td>${item.full}</td></tr>`).join("");
  const sources=[...new Set(state.alerts.map(a=>a.dataSource))];document.getElementById("logSourceGrid").innerHTML=sources.map(source=>{const count=state.alerts.filter(a=>a.dataSource===source).length,latency=hashString(source)%12+1,coverage=Math.max(72,100-latency*2),status=latency>8?"Degraded":"Healthy";return `<div class="log-source"><div><strong>${escapeHTML(source)}</strong><span class="${status==="Healthy"?"ok":"warn"}">${status}</span></div><p>${count} detections • ${latency}m ingestion latency</p><div class="bar"><span style="width:${coverage}%"></span></div><small>${coverage}% telemetry coverage</small></div>`}).join("");
}

function renderAll(){renderKPIs();renderSeverity();renderChart();renderTelemetryHealth();renderRecent();renderMitre();renderAlerts();renderIncidents();renderHistory();renderAssets();renderDetections()}

function switchView(view){
  document.querySelectorAll(".view").forEach(element=>element.classList.remove("active"));const target=document.getElementById(`${view}View`);if(target)target.classList.add("active");document.querySelectorAll(".nav-item").forEach(button=>button.classList.toggle("active",button.dataset.view===view));if(view==="alerts")renderAlerts();if(view==="incidents")renderIncidents();if(view==="history")renderHistory();if(view==="assets")renderAssets();if(view==="detection")renderDetections();
}

function investigationRequirements(alert){
  const visited=new Set(alert.progress?.visitedTabs||[]),requirements=[
    {label:"Alert context",complete:visited.has("overview")},
    {label:"Timeline correlation",complete:visited.has("timeline")},
    {label:"IOC / IP enrichment",complete:visited.has("intel")},
    {label:"Scope and impact",complete:visited.has("scope")},
    {label:"Telemetry reviewed",complete:["process","network","auth","raw"].some(tab=>visited.has(tab))}
  ];
  return {requirements,ready:requirements.every(item=>item.complete),visited:EVIDENCE_TABS.filter(tab=>visited.has(tab)).length};
}

function renderInvestigationProgress(alert){
  const result=investigationRequirements(alert),percent=Math.round(result.requirements.filter(item=>item.complete).length/result.requirements.length*100);document.getElementById("investigationProgress").innerHTML=`<div class="progress-copy"><span>Investigation readiness</span><strong>${percent}%</strong></div><div class="readiness-bar"><span style="width:${percent}%"></span></div><div class="requirement-chips">${result.requirements.map(item=>`<span class="${item.complete?"done":""}">${item.complete?"✓":"○"} ${escapeHTML(item.label)}</span>`).join("")}</div>`;
}

function openInvestigation(id){
  const alert=state.alerts.find(item=>item.id===id);if(!alert)return;state.selectedId=id;if(alert.status==="New")alert.status="In Progress";alert.progress=alert.progress||{visitedTabs:[]};alert.progress.openedAt=alert.progress.openedAt||new Date().toISOString();alert.progress.lastViewedAt=new Date().toISOString();
  document.getElementById("drawerId").textContent=`${alert.id} • ${alert.ruleId} • ${alert.technique}`;document.getElementById("drawerTitle").textContent=alert.name;document.getElementById("drawerSummary").textContent=alert.summary;document.getElementById("dHost").textContent=alert.host;document.getElementById("dUser").textContent=alert.user;document.getElementById("dIp").textContent=alert.ip;document.getElementById("dSeverity").textContent=alert.severity;document.getElementById("dRisk").textContent=`${alert.riskScore}/100`;document.getElementById("dConfidence").textContent=alert.confidence;document.getElementById("dComplexity").textContent=alert.complexity;document.getElementById("dSource").textContent=alert.dataSource;
  const banner=document.getElementById("savedBanner");if(alert.decision){banner.classList.remove("hidden");banner.textContent=`✓ Investigated ${alert.decision.submittedAt}. Saved: ${alert.decision.classification} • ${alert.decision.action} • ${alert.decision.score}/${alert.decision.scoreMax||MAX_SCORE}.`}else banner.classList.add("hidden");
  document.getElementById("investigationDrawer").classList.add("open");document.getElementById("investigationDrawer").setAttribute("aria-hidden","false");document.getElementById("drawerBackdrop").classList.remove("hidden");activateDrawerTab("overview");saveState();renderAll();
}

function closeDrawer(){document.getElementById("investigationDrawer").classList.remove("open");document.getElementById("investigationDrawer").setAttribute("aria-hidden","true");document.getElementById("drawerBackdrop").classList.add("hidden")}

function emptyEvidence(message){return `<div class="empty-evidence"><strong>No records in this source</strong><p>${escapeHTML(message)}</p></div>`}

function activateDrawerTab(tab){
  document.querySelectorAll("#drawerTabs .tab").forEach(button=>button.classList.toggle("active",button.dataset.tab===tab));const alert=state.alerts.find(item=>item.id===state.selectedId);if(!alert)return;alert.progress=alert.progress||{visitedTabs:[]};if(EVIDENCE_TABS.includes(tab)&&!alert.progress.visitedTabs.includes(tab)){alert.progress.visitedTabs.push(tab);saveState()}renderInvestigationProgress(alert);
  const content=document.getElementById("drawerContent"),evidence=alert.evidence;
  if(tab==="overview"){
    content.innerHTML=`<div class="analyst-mission"><div><span class="eyebrow">YOUR TASK</span><strong>Decide whether the source is suspicious, whether the endpoint or identity is affected, and what L1 action is justified.</strong></div><span class="risk-pill ${riskClass(alert.riskScore)}">Risk ${alert.riskScore}</span></div><div class="detection-context"><div><span>Detection rule</span><strong>${escapeHTML(alert.ruleId)}</strong></div><div><span>Product</span><strong>${escapeHTML(alert.product)}</strong></div><div><span>Events correlated</span><strong>${escapeHTML(alert.eventCount)}</strong></div><div><span>Telemetry complete</span><strong>${escapeHTML(alert.logCompleteness)}</strong></div></div><div class="evidence-grid">${evidence.overview.map(item=>`<div class="evidence-card ${escapeHTML(item.tone||"")}"><span>${escapeHTML(item.label)}</span><h3>${escapeHTML(item.value)}</h3></div>`).join("")}</div>`;
  }
  if(tab==="timeline")content.innerHTML=evidence.timeline.length?`<div class="timeline">${evidence.timeline.map(item=>`<div class="timeline-item"><strong>${escapeHTML(item.time)}</strong><span><b>${escapeHTML(item.event)}</b><small>${escapeHTML(item.source)} • ${escapeHTML(item.significance)}</small></span></div>`).join("")}</div>`:emptyEvidence("No correlated timeline events were available.");
  if(tab==="process")content.innerHTML=evidence.process.length?`<div class="table-wrap"><table class="evidence-table"><thead><tr><th>Image</th><th>PID</th><th>Parent</th><th>Command line</th><th>Signer</th><th>Assessment</th><th>Hash</th></tr></thead><tbody>${evidence.process.map(item=>`<tr><td><strong>${escapeHTML(item.image)}</strong></td><td>${escapeHTML(item.pid)}</td><td>${escapeHTML(item.parent)}</td><td class="wrap-cell">${escapeHTML(item.command)}</td><td>${escapeHTML(item.signature)}</td><td>${escapeHTML(item.verdict)}</td><td class="mono">${escapeHTML(item.hash)}</td></tr>`).join("")}</tbody></table></div>`:emptyEvidence("This detection has no endpoint process telemetry. Use other sources and mark endpoint impact as inconclusive if necessary.");
  if(tab==="network")content.innerHTML=evidence.network.length?`<div class="table-wrap"><table class="evidence-table"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Direction</th><th>Bytes</th><th>Assessment</th></tr></thead><tbody>${evidence.network.map(item=>`<tr><td>${escapeHTML(item.time)}</td><td>${escapeHTML(item.src)}</td><td>${escapeHTML(item.dest)}</td><td>${escapeHTML(item.port)}</td><td>${escapeHTML(item.protocol)}</td><td>${escapeHTML(item.direction)}</td><td>${escapeHTML(item.bytes)}</td><td>${escapeHTML(item.assessment)}</td></tr>`).join("")}</tbody></table></div>`:emptyEvidence("No network connections were correlated with this case.");
  if(tab==="auth")content.innerHTML=evidence.auth.length?`<div class="table-wrap"><table class="evidence-table"><thead><tr><th>Time</th><th>Event ID</th><th>Logon / Event</th><th>Result</th><th>IP</th><th>Device</th><th>MFA</th></tr></thead><tbody>${evidence.auth.map(item=>`<tr><td>${escapeHTML(item.time)}</td><td>${escapeHTML(item.eventId)}</td><td>${escapeHTML(item.type)}</td><td>${escapeHTML(item.result)}</td><td>${escapeHTML(item.ip)}</td><td>${escapeHTML(item.device)}</td><td>${escapeHTML(item.mfa)}</td></tr>`).join("")}</tbody></table></div>`:emptyEvidence("No authentication records matched the case window.");
  if(tab==="intel"){
    const intel=evidence.intel||{};content.innerHTML=`<div class="intel-hero"><div><span>IOC under review</span><strong>${escapeHTML(intel.ioc||alert.ip)}</strong><small>${escapeHTML(intel.geo||"Unknown location")} • ${escapeHTML(intel.asn||"Unknown ASN")}</small></div><div class="intel-score ${riskClass(Number(intel.score)||0)}"><b>${escapeHTML(intel.score??"—")}</b><span>reputation score</span></div></div><div class="evidence-grid"><div class="evidence-card"><span>Aggregated verdict</span><h3>${escapeHTML(intel.verdict||"Unknown")}</h3></div><div class="evidence-card"><span>Community reports</span><h3>${escapeHTML(intel.reports??0)}</h3></div><div class="evidence-card"><span>First observed</span><h3>${escapeHTML(intel.firstSeen||"Unknown")}</h3></div><div class="evidence-card"><span>Internal prevalence</span><h3>${escapeHTML(intel.internalPrevalence||"Unknown")}</h3></div><div class="evidence-card"><span>Allowlist match</span><h3>${intel.allowlisted?"Yes":"No"}</h3></div><div class="evidence-card"><span>Tags</span><h3>${escapeHTML((intel.tags||[]).join(", ")||"None")}</h3></div></div><div class="intel-note"><strong>Analyst note:</strong> Reputation is supporting evidence, not a final verdict. Correlate it with timeline, authentication, process and scope data.</div>`;
  }
  if(tab==="scope"){
    content.innerHTML=`<div class="entity-grid"><div class="entity-card"><span>AFFECTED ASSET</span><h3>${escapeHTML(alert.asset.hostname)}</h3><p>${escapeHTML(alert.asset.ip)} • ${escapeHTML(alert.asset.os)}</p><dl><div><dt>Criticality</dt><dd>${escapeHTML(alert.asset.criticality)}</dd></div><div><dt>Department</dt><dd>${escapeHTML(alert.asset.department)}</dd></div><div><dt>EDR state</dt><dd>${escapeHTML(alert.asset.edrStatus)}</dd></div></dl></div><div class="entity-card"><span>IDENTITY CONTEXT</span><h3>${escapeHTML(alert.identity.username)}</h3><p>${escapeHTML(alert.identity.department)} • ${escapeHTML(alert.identity.privilege)}</p><dl><div><dt>MFA</dt><dd>${escapeHTML(alert.identity.mfa)}</dd></div><div><dt>Account age</dt><dd>${escapeHTML(alert.identity.accountAge)}</dd></div><div><dt>Case role</dt><dd>${escapeHTML(alert.user===alert.identity.username?"Observed user":"Related identity")}</dd></div></dl></div></div><div class="table-wrap scope-table"><table><thead><tr><th>Entity</th><th>Type</th><th>Related events</th><th>Last seen</th><th>Assessment</th></tr></thead><tbody>${evidence.scope.map(item=>`<tr><td><strong>${escapeHTML(item.entity)}</strong></td><td>${escapeHTML(item.type)}</td><td>${escapeHTML(item.alerts)}</td><td>${escapeHTML(item.lastSeen)}</td><td>${escapeHTML(item.status)}</td></tr>`).join("")}</tbody></table></div>`;
  }
  if(tab==="raw")content.innerHTML=evidence.raw.length?`<div class="raw-log-head"><strong>Raw event samples</strong><span>Use these fields to verify the normalized evidence.</span></div><div class="raw-logs">${evidence.raw.map((line,index)=>`<div><span>${String(index+1).padStart(2,"0")}</span><code>${escapeHTML(line)}</code></div>`).join("")}</div>`:emptyEvidence("No raw event sample is available for this source.");
  if(tab==="decision")renderDecision(alert,content);
}

function optionList(values){return '<option value="">Choose...</option>'+values.map(value=>`<option>${escapeHTML(value)}</option>`).join("")}

function renderDecision(alert,content){
  const decision=alert.decision,readiness=investigationRequirements(alert),saved=decision?`<div class="decision-summary"><div><span>Saved classification</span><strong>${escapeHTML(decision.classification)}</strong></div><div><span>Saved L1 action</span><strong>${escapeHTML(decision.action)}</strong></div><div><span>Assessment score</span><strong>${escapeHTML(decision.score)}/${escapeHTML(decision.scoreMax||MAX_SCORE)} • ${escapeHTML(decision.submittedAt)}</strong></div></div>`:"";
  content.innerHTML=`${saved}<div class="decision-readiness ${readiness.ready?"ready":"not-ready"}"><strong>${readiness.ready?"✓ Evidence review complete":"Investigation not ready"}</strong><span>${readiness.ready?"Record your evidence-based disposition below.":"Review Overview, Timeline, Intel / IP, Scope & Impact and at least one telemetry tab before submitting."}</span></div><form id="decisionForm" class="decision-form"><div class="decision-grid"><label>Classification<select id="classification">${optionList(["True Positive","False Positive","Needs More Investigation"])}</select></label><label>Final Severity<select id="decisionSeverity">${optionList(["Critical","High","Medium","Low"])}</select></label><label>Source / IOC Assessment<select id="ipAssessment">${optionList(["Suspicious","Benign","Inconclusive"])}</select></label><label>Endpoint Impact<select id="endpointImpact">${optionList(["Confirmed","Not affected","Inconclusive"])}</select></label><label>Compromise Status<select id="compromise">${optionList(["Confirmed","Not confirmed","Inconclusive"])}</select></label><label>L1 Action<select id="decisionAction">${optionList(ACTIONS)}</select></label></div><label>Evidence-based Analyst Notes <span class="field-hint">minimum 25 characters</span><textarea id="analystNotes" placeholder="Example: 186 VPN failures from a malicious IP; no successful authentication; endpoint telemetry shows no impact. Recommend blocking source and monitoring the account."></textarea></label><button class="primary" type="submit">${decision?"Update Investigation":"Submit Investigation"}</button><div id="decisionFeedback" class="feedback">Your six decisions are scored against the evidence. Notes and progress are saved locally.</div></form>`;
  if(decision){document.getElementById("classification").value=decision.classification;document.getElementById("decisionSeverity").value=decision.severity;document.getElementById("ipAssessment").value=decision.ipAssessment;document.getElementById("endpointImpact").value=decision.endpointImpact;document.getElementById("compromise").value=decision.compromise;document.getElementById("decisionAction").value=decision.action}document.getElementById("analystNotes").value=alert.note||"";document.getElementById("decisionForm").addEventListener("submit",submitDecision);
}

function submitDecision(event){
  event.preventDefault();const alert=state.alerts.find(item=>item.id===state.selectedId),feedback=document.getElementById("decisionFeedback"),readiness=investigationRequirements(alert);if(!readiness.ready){feedback.className="feedback warn";feedback.textContent="Complete the evidence review checklist before submitting the case.";return}
  const values={classification:document.getElementById("classification").value,severity:document.getElementById("decisionSeverity").value,ipAssessment:document.getElementById("ipAssessment").value,endpointImpact:document.getElementById("endpointImpact").value,compromise:document.getElementById("compromise").value,action:document.getElementById("decisionAction").value},note=document.getElementById("analystNotes").value.trim();
  if(Object.values(values).some(value=>!value)){feedback.className="feedback warn";feedback.textContent="Choose all six assessment fields first.";return}if(note.length<25){feedback.className="feedback warn";feedback.textContent="Add evidence-based notes with at least 25 characters.";return}
  const fields=["classification","severity","action","ipAssessment","endpointImpact","compromise"],score=fields.reduce((total,key)=>total+(values[key]===alert.expected[key]?1:0),0),iso=new Date().toISOString();alert.note=note;alert.decision={...values,score,scoreMax:MAX_SCORE,submittedAt:nowStamp(),submittedAtISO:iso,escalationSummary:`${alert.id} | ${values.classification} | ${values.severity} | ${alert.host} / ${alert.user} | ${values.action}. ${note}`};
  if(["Escalate to L2 / Incident Response","Contain Host and Escalate","Disable Account and Escalate"].includes(values.action)){alert.status="Escalated";alert.owner="SOC L2 / IR"}else if(values.action==="Close as False Positive"){alert.status="Closed";alert.owner="SOC L1"}else{alert.status="In Progress";alert.owner="SOC L1"}
  saveState();feedback.className=`feedback ${score===MAX_SCORE?"good":"warn"}`;feedback.innerHTML=`<strong>Saved • Score ${score}/${MAX_SCORE}</strong><br>Expected: ${fields.map(key=>escapeHTML(alert.expected[key])).join(" • ")}<br>${score===MAX_SCORE?"Correct evidence-based triage.":"Compare your choices with the evidence and revise if needed."}`;const banner=document.getElementById("savedBanner");banner.classList.remove("hidden");banner.textContent=`✓ Investigation saved. Reopening this alert keeps the decision, notes and evidence-review progress.`;renderAll();
}

function scenarioLabel(scenario){return ({auth_bruteforce:"Authentication Brute Force",impossible_travel:"Impossible Travel",powershell:"Suspicious PowerShell",phishing:"Phishing",scheduled_task:"Scheduled Task Persistence",ransomware:"Ransomware Behavior",credential_dump:"Credential Dumping",defense_evasion:"Security Control Tampering",beaconing:"Malware Beaconing",dns_tunnel:"DNS Tunneling",privilege_escalation:"Privilege Escalation",lateral_movement:"Lateral Movement",web_shell:"Web Shell",oauth_consent:"Risky OAuth Consent",usb_exfil:"USB Data Exfiltration",approved_scanner:"Approved Vulnerability Scanner"})[scenario.key]||scenario.key}

function populateAlertForm(){const select=document.getElementById("newTemplate");select.innerHTML=SCENARIOS.map((scenario,index)=>`<option value="${index}">${escapeHTML(scenarioLabel(scenario))}</option>`).join("");fillAlertFormFromTemplate(0)}

function fillAlertFormFromTemplate(index){
  const sample=createGeneratedAlert(9000+index,state.datasetSeed,index);document.getElementById("newName").value=sample.name;document.getElementById("newSeverity").value=sample.severity;document.getElementById("newMitre").value=sample.mitre;document.getElementById("newSummary").value=sample.summary;document.getElementById("newHost").value=sample.host;document.getElementById("newUser").value=sample.user;document.getElementById("newIp").value=sample.ip;
}

function showAlertModal(){populateAlertForm();document.getElementById("alertModal").classList.remove("hidden");document.getElementById("modalBackdrop").classList.remove("hidden");document.getElementById("newName").focus()}
function hideAlertModal(){document.getElementById("alertModal").classList.add("hidden");document.getElementById("modalBackdrop").classList.add("hidden")}

function replaceEvidenceValues(value,replacements){
  if(Array.isArray(value))return value.map(item=>replaceEvidenceValues(item,replacements));if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,replaceEvidenceValues(item,replacements)]));if(typeof value!=="string")return value;return replacements.reduce((text,[from,to])=>from?text.split(from).join(to):text,value);
}

function addCustomAlert(event){
  event.preventDefault();const scenarioIndex=Number(document.getElementById("newTemplate").value),sequence=state.alerts.length+int(rngFrom(Date.now()),100,9000),alert=createGeneratedAlert(sequence,state.datasetSeed,scenarioIndex),old={host:alert.host,user:alert.user,ip:alert.ip};
  alert.id=`CUS-${String(Date.now()).slice(-8)}`;alert.detectedAt=new Date().toISOString();alert.time=formatDateTime(alert.detectedAt);alert.name=document.getElementById("newName").value.trim();alert.severity=document.getElementById("newSeverity").value;alert.expected.severity=alert.severity;alert.host=document.getElementById("newHost").value.trim();alert.user=document.getElementById("newUser").value.trim();alert.ip=document.getElementById("newIp").value.trim();alert.mitre=document.getElementById("newMitre").value.trim();alert.summary=document.getElementById("newSummary").value.trim();alert.custom=true;
  alert.asset={...(ASSETS.find(item=>item.hostname===alert.host)||alert.asset),hostname:alert.host};alert.identity={...(IDENTITIES.find(item=>item.username===alert.user)||alert.identity),username:alert.user};alert.evidence=replaceEvidenceValues(alert.evidence,[[old.host,alert.host],[old.user,alert.user],[old.ip,alert.ip]]);if(alert.evidence.intel)alert.evidence.intel.ioc=alert.ip;
  state.alerts.unshift(alert);state.page=1;saveState();renderAll();hideAlertModal();switchView("alerts");openInvestigation(alert.id);
}

function exportProgress(){
  const payload={app:"SOC L1 Investigation Lab",version:STORAGE_VERSION,exportedAt:new Date().toISOString(),datasetSeed:state.datasetSeed,alerts:state.alerts};const blob=new Blob([JSON.stringify(payload,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),link=document.createElement("a");link.href=url;link.download=`soc-l1-lab-v3-progress-${new Date().toISOString().slice(0,10)}.json`;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);
}

function importProgress(file){
  const reader=new FileReader();reader.onload=()=>{try{const data=JSON.parse(String(reader.result));if(!data||!Array.isArray(data.alerts)||!data.alerts.length)throw new Error("No alerts found");state.datasetSeed=Number(data.datasetSeed)||Date.now();state.alerts=data.alerts.map((alert,index)=>normalizeAlert(alert,index,state.datasetSeed));state.alerts.sort((a,b)=>String(b.detectedAt).localeCompare(String(a.detectedAt)));state.page=1;saveState();renderAll();alert(`Imported ${state.alerts.length} alerts. v2 files are automatically upgraded with fresh v3 evidence.`)}catch(error){alert("Could not import this progress file: "+error.message)}};reader.readAsText(file);
}

function resetLab(){if(!confirm("Reset the lab? This deletes locally saved progress and generates a completely fresh set of 560 alerts with new times, counts, entities and evidence."))return;try{localStorage.removeItem(STORAGE_KEY);localStorage.removeItem(LEGACY_STORAGE_KEY)}catch{}generateAlerts(DATASET_SIZE);switchView("overview")}

document.querySelectorAll(".nav-item").forEach(button=>button.addEventListener("click",()=>switchView(button.dataset.view)));
document.querySelectorAll("[data-go-alerts]").forEach(button=>button.addEventListener("click",()=>switchView("alerts")));
document.getElementById("searchInput").addEventListener("input",()=>{state.page=1;renderAlerts()});
["severityFilter","statusFilter","complexityFilter"].forEach(id=>document.getElementById(id).addEventListener("change",()=>{state.page=1;renderAlerts()}));
document.getElementById("prevPage").addEventListener("click",()=>{if(state.page>1){state.page--;renderAlerts()}});
document.getElementById("nextPage").addEventListener("click",()=>{const max=Math.ceil(getFiltered().length/state.pageSize);if(state.page<max){state.page++;renderAlerts()}});
document.getElementById("newCaseBtn").addEventListener("click",showAlertModal);
document.getElementById("closeModal").addEventListener("click",hideAlertModal);document.getElementById("cancelModal").addEventListener("click",hideAlertModal);document.getElementById("modalBackdrop").addEventListener("click",hideAlertModal);
document.getElementById("newTemplate").addEventListener("change",event=>fillAlertFormFromTemplate(Number(event.target.value)));document.getElementById("addAlertForm").addEventListener("submit",addCustomAlert);
document.getElementById("exportBtn").addEventListener("click",exportProgress);document.getElementById("importBtn").addEventListener("click",()=>document.getElementById("importFile").click());document.getElementById("importFile").addEventListener("change",event=>{if(event.target.files?.[0])importProgress(event.target.files[0]);event.target.value=""});document.getElementById("resetBtn").addEventListener("click",resetLab);
document.getElementById("closeDrawer").addEventListener("click",closeDrawer);document.getElementById("drawerBackdrop").addEventListener("click",closeDrawer);document.querySelectorAll("#drawerTabs .tab").forEach(button=>button.addEventListener("click",()=>activateDrawerTab(button.dataset.tab)));
document.addEventListener("keydown",event=>{if(event.key==="Escape"){closeDrawer();hideAlertModal()}});

if(!loadState())generateAlerts(DATASET_SIZE);else renderAll();
