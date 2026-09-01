const STORAGE_KEY = "socL1PracticeLab.v2";
const STORAGE_VERSION = 2;

const state = {
  alerts: [],
  selectedId: null,
  page: 1,
  pageSize: 40,
  storageAvailable: true
};

const ALERT_TEMPLATES = [
  {name:"Suspicious PowerShell Execution",severity:"Critical",mitre:"Execution",answer:["True Positive","Critical","Escalate to L2 / Incident Response"],summary:"Encoded PowerShell launched from a user endpoint shortly after a document process.",overview:["PowerShell uses an encoded command","Parent process is WINWORD.EXE","Outbound connection follows execution","EDR confidence is high"],process:["WINWORD.EXE","powershell.exe -EncodedCommand","cmd.exe /c whoami","rundll32.exe"],network:[["203.0.113.77","443","Outbound","Rare / suspicious"],["10.10.10.5","53","DNS","Normal resolver"]],auth:[["10:15:01","Interactive","Success"],["10:25:03","Remote","No success"]],intel:["203.0.113.77","Malicious in training dataset","High"]},
  {name:"Brute Force Attempt",severity:"High",mitre:"Credential Access",answer:["Needs More Investigation","High","Request More Logs / Enrichment"],summary:"Repeated authentication failures from a previously unseen public source.",overview:["45 failures in 4 minutes","No confirmed successful login","Target account is sensitive","Source IP is new to environment"],process:["VPN authentication service","No endpoint process telemetry"],network:[["198.51.100.44","443","Inbound","Unfamiliar external source"]],auth:[["09:53:12","VPN","Failed"],["09:54:55","VPN","Failed"],["09:57:44","VPN","Failed"]],intel:["198.51.100.44","Unknown / low-confidence reputation","Low"]},
  {name:"Malware Beaconing",severity:"High",mitre:"Command and Control",answer:["Needs More Investigation","High","Request More Logs / Enrichment"],summary:"A workstation is making highly periodic TLS connections to a rare destination.",overview:["Connections every 60 seconds","Destination is rare","Process ancestry incomplete","No confirmed malicious hash"],process:["svchost.exe","unknown child context"],network:[["192.0.2.66","443","Outbound","60-second periodicity"]],auth:[["08:10:22","Interactive","Success"]],intel:["192.0.2.66","Suspicious in training dataset","Medium"]},
  {name:"Privilege Escalation",severity:"Critical",mitre:"Privilege Escalation",answer:["True Positive","Critical","Escalate to L2 / Incident Response"],summary:"A service account was added to the local Administrators group outside maintenance.",overview:["Event ID 4732 observed","No approved change ticket","Service account normally low privilege","Production host affected"],process:["w3wp.exe","cmd.exe","net.exe localgroup administrators websvc /add"],network:[["10.11.4.17","5985","Internal","Unusual WinRM administration"]],auth:[["07:30:52","Network logon","Success"],["07:31:05","Special privileges","Observed"]],intel:["websvc","Internal account; anomalous privilege change","High"]},
  {name:"Phishing Link Clicked",severity:"Medium",mitre:"Initial Access",answer:["Needs More Investigation","Medium","Request More Logs / Enrichment"],summary:"A user clicked a suspicious email URL but compromise is not yet confirmed.",overview:["URL clicked from corporate email","Browser opened rare domain","No payload confirmed","EDR shows no immediate execution"],process:["OUTLOOK.EXE","msedge.exe"],network:[["203.0.113.129","443","Outbound","Rare destination"]],auth:[["11:06:10","Interactive","Success"]],intel:["203.0.113.129","Recently observed / uncertain","Medium"]},
  {name:"Known Vulnerability Scanner",severity:"Low",mitre:"Discovery",answer:["False Positive","Low","Close as False Positive"],summary:"Internal scanner generated high-volume port activity during an approved assessment window.",overview:["Source belongs to registered scanner","Approved change ticket exists","Time matches scan window","No follow-on exploitation"],process:["scanner-agent.exe","approved service account"],network:[["10.20.5.10","1-65535","Internal scan","Expected"]],auth:[["09:29:50","Service logon","Success"]],intel:["10.20.5.10","Known internal scanner","High"]},
  {name:"Impossible Travel Login",severity:"Medium",mitre:"Credential Access",answer:["Needs More Investigation","Medium","Request More Logs / Enrichment"],summary:"Two successful logins appear geographically inconsistent within a short interval.",overview:["Two locations within 18 minutes","VPN usage is possible","Device fingerprint partly matches","MFA success recorded"],process:["Cloud authentication only"],network:[["198.51.100.90","443","Inbound","Cloud login"]],auth:[["12:05:11","Cloud login","Success"],["12:23:02","Cloud login","Success"]],intel:["198.51.100.90","No negative reputation","Low"]},
  {name:"Suspicious Scheduled Task",severity:"High",mitre:"Persistence",answer:["True Positive","High","Escalate to L2 / Incident Response"],summary:"A newly created scheduled task launches a script from a user-writable directory.",overview:["Task created outside change window","Executable located in AppData","Parent process is suspicious","User does not normally administer host"],process:["explorer.exe","cmd.exe","schtasks.exe /create","powershell.exe"],network:[["203.0.113.88","443","Outbound","Rare destination"]],auth:[["06:42:19","Interactive","Success"]],intel:["203.0.113.88","Suspicious in training dataset","High"]}
];

const HOSTS=["WIN-FIN-07","WIN-HR-14","LAP-DEV-17","SRV-APP-02","DC-01","VPN-GW-01","WIN-3G9P2Q1","SRV-WEB-02","WIN-7FJ8K2L","LAP-SALES-11","SRV-DB-03","WIN-OPS-09"];
const USERS=["jsingh","rmehta","websvc","admin-support","user.j.smith","svc_scanner","akumar","mverma","nsharma","helpdesk01","svc_backup","priya"];
const IPS=["10.10.15.23","198.51.100.44","203.0.113.77","192.0.2.66","10.20.5.10","203.0.113.129","198.51.100.90","203.0.113.88","10.11.4.17","192.168.1.45"];

function rand(arr){return arr[Math.floor(Math.random()*arr.length)]}
function pad(n){return String(n).padStart(2,"0")}
function randomTime(){return `${pad(Math.floor(Math.random()*24))}:${pad(Math.floor(Math.random()*60))}:${pad(Math.floor(Math.random()*60))}`}
function nowStamp(){return new Date().toLocaleString()}
function escapeHTML(value){return String(value??"").replace(/[&<>'"]/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[ch]))}
function getTemplate(alert){return ALERT_TEMPLATES[Math.max(0,Math.min(ALERT_TEMPLATES.length-1,Number(alert.templateIndex)||0))]}
function expectedFor(alert){const t=getTemplate(alert);return [t.answer[0],alert.expectedSeverity||t.answer[1],t.answer[2]]}
function sevDot(sev){const color=sev==="Critical"?"var(--red)":sev==="High"?"var(--orange)":sev==="Medium"?"var(--yellow)":"var(--green)";return `<span class="dot" style="background:${color}"></span>`}

function setSaveLabel(text,ok=true){
  [document.getElementById("saveState"),document.getElementById("saveStateSide")].forEach(el=>{if(!el)return;el.textContent=(ok?"● ":"⚠ ")+text;el.classList.toggle("good",ok);el.classList.toggle("warn",!ok)});
}

function saveState(){
  const payload={version:STORAGE_VERSION,savedAt:new Date().toISOString(),alerts:state.alerts};
  try{
    localStorage.setItem(STORAGE_KEY,JSON.stringify(payload));
    state.storageAvailable=true;setSaveLabel("Saved locally",true);
  }catch(err){
    state.storageAvailable=false;setSaveLabel("Storage unavailable — export progress",false);
    console.warn("Local storage unavailable",err);
  }
}

function loadState(){
  try{
    const raw=localStorage.getItem(STORAGE_KEY);if(!raw)return false;
    const data=JSON.parse(raw);
    if(!data||!Array.isArray(data.alerts)||!data.alerts.length)return false;
    state.alerts=data.alerts.map(normalizeAlert);state.storageAvailable=true;setSaveLabel("Progress restored",true);return true;
  }catch(err){console.warn("Could not restore saved state",err);return false}
}

function normalizeAlert(a){
  return {
    id:String(a.id||"ALT-UNKNOWN"),time:String(a.time||randomTime()),name:String(a.name||"Untitled Alert"),severity:["Critical","High","Medium","Low"].includes(a.severity)?a.severity:"Medium",
    host:String(a.host||"UNKNOWN-HOST"),user:String(a.user||"unknown"),ip:String(a.ip||"0.0.0.0"),status:["New","In Progress","Escalated","Closed"].includes(a.status)?a.status:"New",
    owner:String(a.owner||"Unassigned"),mitre:String(a.mitre||"Unknown"),templateIndex:Number.isInteger(Number(a.templateIndex))?Number(a.templateIndex):0,
    summary:String(a.summary||""),expectedSeverity:String(a.expectedSeverity||a.severity||"Medium"),custom:Boolean(a.custom),note:String(a.note||""),decision:a.decision&&typeof a.decision==="object"?a.decision:null
  };
}

function generateAlerts(count=560){
  state.alerts=[];
  for(let i=0;i<count;i++){
    const templateIndex=i%ALERT_TEMPLATES.length,t=ALERT_TEMPLATES[templateIndex];
    state.alerts.push({id:`ALT-${String(i+1).padStart(5,"0")}`,time:randomTime(),name:t.name,severity:t.severity,host:rand(HOSTS),user:rand(USERS),ip:rand(IPS),status:"New",owner:"Unassigned",mitre:t.mitre,templateIndex,summary:t.summary,expectedSeverity:t.severity,custom:false,note:"",decision:null});
  }
  state.page=1;saveState();renderAll();
}

function investigatedAlerts(){return state.alerts.filter(a=>a.decision)}
function escalatedAlerts(){return state.alerts.filter(a=>a.status==="Escalated")}
function accuracy(){const d=investigatedAlerts();if(!d.length)return null;return Math.round(d.filter(a=>Number(a.decision.score)===3).length/d.length*100)}

function getFiltered(){
  const q=document.getElementById("searchInput").value.trim().toLowerCase(),sev=document.getElementById("severityFilter").value,st=document.getElementById("statusFilter").value;
  return state.alerts.filter(a=>{const hay=[a.id,a.name,a.host,a.user,a.ip].join(" ").toLowerCase();return(!q||hay.includes(q))&&(!sev||a.severity===sev)&&(!st||a.status===st)});
}

function renderKPIs(){
  const open=state.alerts.filter(a=>a.status!=="Closed").length,critical=state.alerts.filter(a=>a.severity==="Critical"&&a.status!=="Closed").length,acc=accuracy();
  document.getElementById("kpiOpen").textContent=open;document.getElementById("kpiCritical").textContent=critical;document.getElementById("kpiInvestigated").textContent=investigatedAlerts().length;document.getElementById("kpiEscalated").textContent=escalatedAlerts().length;document.getElementById("kpiAccuracy").textContent=acc===null?"—":acc+"%";
}

function renderSeverity(){
  const counts={Critical:0,High:0,Medium:0,Low:0};state.alerts.filter(a=>a.status!=="Closed").forEach(a=>counts[a.severity]++);const total=Object.values(counts).reduce((a,b)=>a+b,0)||1;
  document.getElementById("donutTotal").textContent=total;const p1=counts.Critical/total*100,p2=counts.High/total*100,p3=counts.Medium/total*100;
  document.getElementById("severityDonut").style.background=`conic-gradient(var(--red) 0 ${p1}%, var(--orange) ${p1}% ${p1+p2}%, var(--yellow) ${p1+p2}% ${p1+p2+p3}%, var(--green) ${p1+p2+p3}% 100%)`;
  document.getElementById("severityLegend").innerHTML=Object.entries(counts).map(([k,v])=>`<div class="legend-row">${sevDot(k)}<span>${k}</span><strong>${v}</strong></div>`).join("");
}

function renderChart(){
  const canvas=document.getElementById("alertsChart"),ctx=canvas.getContext("2d"),data=Array(24).fill(0);state.alerts.forEach(a=>{const h=parseInt(a.time.slice(0,2),10);if(Number.isFinite(h)&&h>=0&&h<24)data[h]++});
  const max=Math.max(...data,1),scale=170/max;ctx.clearRect(0,0,canvas.width,canvas.height);ctx.strokeStyle="#20364f";ctx.lineWidth=1;
  for(let y=30;y<230;y+=50){ctx.beginPath();ctx.moveTo(42,y);ctx.lineTo(740,y);ctx.stroke()}
  ctx.strokeStyle="#2d8cff";ctx.lineWidth=3;ctx.beginPath();data.forEach((v,i)=>{const x=45+i*(690/23),y=215-v*scale;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y)});ctx.stroke();ctx.fillStyle="#94a8bd";ctx.font="11px system-ui";[0,6,12,18,23].forEach(i=>ctx.fillText(`${pad(i)}:00`,40+i*(690/23),248));
}

function progressMark(a){return a.decision?'<span class="investigated-mark">✓ Investigated</span>':a.status==="In Progress"?'<span class="muted-mark">In progress</span>':'<span class="muted-mark">Not started</span>'}

function renderRecent(){
  const rows=state.alerts.filter(a=>["Critical","High"].includes(a.severity)).slice(0,8);document.getElementById("recentTable").innerHTML=rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.time)}</td><td>${escapeHTML(a.name)}</td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td>${escapeHTML(a.host)}</td><td>${progressMark(a)}</td></tr>`).join("");
  document.querySelectorAll("#recentTable tr").forEach(tr=>tr.addEventListener("click",()=>openInvestigation(tr.dataset.id)));
}

function renderMitre(){const cov=[["Initial Access",85],["Execution",92],["Persistence",76],["Credential Access",81],["Privilege Escalation",72],["Command and Control",68]];document.getElementById("mitreCoverage").innerHTML=cov.map(([n,p])=>`<div class="cov-row"><span>${n}</span><div class="bar"><span style="width:${p}%"></span></div><b>${p}%</b></div>`).join("")}

function renderAlerts(){
  const filtered=getFiltered();document.getElementById("alertCountText").textContent=filtered.length;const maxPage=Math.max(1,Math.ceil(filtered.length/state.pageSize));if(state.page>maxPage)state.page=maxPage;const start=(state.page-1)*state.pageSize,rows=filtered.slice(start,start+state.pageSize);
  document.getElementById("alertsTable").innerHTML=rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.time)}</td><td>${escapeHTML(a.name)}${a.custom?' <span class="badge">Custom</span>':''}</td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td>${escapeHTML(a.host)}</td><td>${escapeHTML(a.user)}</td><td>${escapeHTML(a.ip)}</td><td><span class="badge">${escapeHTML(a.status)}</span></td><td>${progressMark(a)}</td></tr>`).join("");
  document.querySelectorAll("#alertsTable tr").forEach(tr=>tr.addEventListener("click",()=>openInvestigation(tr.dataset.id)));document.getElementById("pageInfo").textContent=`Page ${state.page} of ${maxPage}`;document.getElementById("prevPage").disabled=state.page<=1;document.getElementById("nextPage").disabled=state.page>=maxPage;
}

function renderIncidents(){
  const rows=escalatedAlerts();document.getElementById("incidentsTable").innerHTML=rows.length?rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.name)}</td><td><span class="sev">${sevDot(a.severity)}${escapeHTML(a.severity)}</span></td><td>${escapeHTML(a.host)}</td><td>${escapeHTML(a.user)}</td><td>${escapeHTML(a.owner)}</td><td>${escapeHTML(a.decision?.submittedAt||"")}</td></tr>`).join(""):`<tr><td colspan="7">No escalated incidents yet.</td></tr>`;
  document.querySelectorAll("#incidentsTable tr[data-id]").forEach(tr=>tr.addEventListener("click",()=>openInvestigation(tr.dataset.id)));
}

function renderHistory(){
  const rows=investigatedAlerts().sort((a,b)=>String(b.decision?.submittedAtISO||"").localeCompare(String(a.decision?.submittedAtISO||"")));
  document.getElementById("historyTable").innerHTML=rows.length?rows.map(a=>`<tr data-id="${escapeHTML(a.id)}"><td>${escapeHTML(a.id)}</td><td>${escapeHTML(a.name)}</td><td>${escapeHTML(a.decision.classification)}</td><td>${escapeHTML(a.decision.severity)}</td><td>${escapeHTML(a.decision.action)}</td><td>${escapeHTML(a.decision.score)}/3</td><td>${escapeHTML(a.decision.submittedAt)}</td></tr>`).join(""):`<tr><td colspan="7">No investigations completed yet.</td></tr>`;
  document.querySelectorAll("#historyTable tr[data-id]").forEach(tr=>tr.addEventListener("click",()=>openInvestigation(tr.dataset.id)));
}

function renderAssets(){const counts={};state.alerts.forEach(a=>counts[a.host]=(counts[a.host]||0)+1);const top=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,12);document.getElementById("assetsGrid").innerHTML=top.map(([host,count],i)=>`<div class="asset"><span>#${i+1} affected asset</span><strong>${escapeHTML(host)}</strong><p>${count} alerts</p></div>`).join("")}
function renderAll(){renderKPIs();renderSeverity();renderChart();renderRecent();renderMitre();renderAlerts();renderIncidents();renderHistory();renderAssets()}

function switchView(view){document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));document.getElementById(view+"View").classList.add("active");document.querySelectorAll(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.view===view));if(view==="alerts")renderAlerts();if(view==="incidents")renderIncidents();if(view==="history")renderHistory();if(view==="assets")renderAssets()}

function openInvestigation(id){
  const a=state.alerts.find(x=>x.id===id);if(!a)return;state.selectedId=id;if(a.status==="New"){a.status="In Progress";saveState()}
  const t=getTemplate(a);document.getElementById("drawerId").textContent=a.id;document.getElementById("drawerTitle").textContent=a.name;document.getElementById("drawerSummary").textContent=a.summary||t.summary;document.getElementById("dHost").textContent=a.host;document.getElementById("dUser").textContent=a.user;document.getElementById("dIp").textContent=a.ip;document.getElementById("dSeverity").textContent=a.severity;
  const banner=document.getElementById("savedBanner");if(a.decision){banner.classList.remove("hidden");banner.textContent=`✓ Already investigated on ${a.decision.submittedAt}. Saved decision: ${a.decision.classification} • ${a.decision.action} • Score ${a.decision.score}/3.`}else banner.classList.add("hidden");
  document.getElementById("investigationDrawer").classList.add("open");document.getElementById("investigationDrawer").setAttribute("aria-hidden","false");document.getElementById("drawerBackdrop").classList.remove("hidden");activateDrawerTab("overview");renderAll();
}
function closeDrawer(){document.getElementById("investigationDrawer").classList.remove("open");document.getElementById("investigationDrawer").setAttribute("aria-hidden","true");document.getElementById("drawerBackdrop").classList.add("hidden")}

function activateDrawerTab(tab){
  document.querySelectorAll("#drawerTabs .tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));const a=state.alerts.find(x=>x.id===state.selectedId);if(!a)return;const c=document.getElementById("drawerContent"),t=getTemplate(a);
  if(tab==="overview")c.innerHTML=`<div class="evidence-grid">${t.overview.map(x=>`<div class="evidence-card">${escapeHTML(x)}</div>`).join("")}</div>`;
  if(tab==="timeline"){const base=["Alert precursor observed","User/process activity starts","Suspicious behavior detected","SIEM correlation triggers","SOC case opened"];c.innerHTML=`<div class="timeline">${base.map((x,i)=>`<div class="timeline-item"><strong>${escapeHTML(a.time.slice(0,5))}:${pad((10+i*7)%60)}</strong><span>${escapeHTML(x)}</span></div>`).join("")}</div>`}
  if(tab==="process")c.innerHTML=`<div class="proc-tree">${t.process.map((x,i)=>`<div class="proc-node">${escapeHTML(x)}</div>${i<t.process.length-1?'<div class="proc-line"></div>':''}`).join("")}</div>`;
  if(tab==="network")c.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Destination</th><th>Port</th><th>Direction</th><th>Assessment</th></tr></thead><tbody>${t.network.map(x=>`<tr><td>${escapeHTML(x[0])}</td><td>${escapeHTML(x[1])}</td><td>${escapeHTML(x[2])}</td><td>${escapeHTML(x[3])}</td></tr>`).join("")}</tbody></table></div>`;
  if(tab==="auth")c.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Logon Type</th><th>Result</th></tr></thead><tbody>${t.auth.map(x=>`<tr><td>${escapeHTML(x[0])}</td><td>${escapeHTML(x[1])}</td><td>${escapeHTML(x[2])}</td></tr>`).join("")}</tbody></table></div>`;
  if(tab==="intel")c.innerHTML=`<div class="evidence-grid"><div class="evidence-card"><span class="tiny">IOC</span><h3>${escapeHTML(t.intel[0])}</h3></div><div class="evidence-card"><span class="tiny">Reputation</span><h3>${escapeHTML(t.intel[1])}</h3></div><div class="evidence-card"><span class="tiny">Confidence</span><h3>${escapeHTML(t.intel[2])}</h3></div><div class="evidence-card"><span class="tiny">MITRE tactic</span><h3>${escapeHTML(a.mitre)}</h3></div></div>`;
  if(tab==="decision")renderDecision(a,c);
}

function renderDecision(a,c){
  const d=a.decision;const saved=d?`<div class="decision-summary"><div><span>Previous classification</span><strong>${escapeHTML(d.classification)}</strong></div><div><span>Previous action</span><strong>${escapeHTML(d.action)}</strong></div><div><span>Previous score</span><strong>${escapeHTML(d.score)}/3 • ${escapeHTML(d.submittedAt)}</strong></div></div>`:"";
  c.innerHTML=`${saved}<form id="decisionForm" class="decision-form"><label>Classification<select id="classification"><option value="">Choose...</option><option>True Positive</option><option>False Positive</option><option>Needs More Investigation</option></select></label><label>Severity<select id="decisionSeverity"><option value="">Choose...</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label><label>L1 Action<select id="decisionAction"><option value="">Choose...</option><option>Escalate to L2 / Incident Response</option><option>Close as False Positive</option><option>Request More Logs / Enrichment</option><option>Monitor Only</option></select></label><label>Analyst Notes<textarea id="analystNotes" placeholder="Write evidence-based findings..."></textarea></label><button class="primary" type="submit">${d?"Update Saved Investigation":"Submit Investigation"}</button><div id="decisionFeedback" class="feedback">${d?"This alert was already investigated. You can review or update the saved decision.":"Use the evidence tabs before submitting your decision."}</div><div class="storage-note">Decisions and notes are automatically saved in this browser. Use Export Progress for a portable backup.</div></form>`;
  if(d){document.getElementById("classification").value=d.classification;document.getElementById("decisionSeverity").value=d.severity;document.getElementById("decisionAction").value=d.action}document.getElementById("analystNotes").value=a.note||"";document.getElementById("decisionForm").addEventListener("submit",submitDecision);
}

function submitDecision(e){
  e.preventDefault();const a=state.alerts.find(x=>x.id===state.selectedId),expected=expectedFor(a),vals=[document.getElementById("classification").value,document.getElementById("decisionSeverity").value,document.getElementById("decisionAction").value];if(vals.some(v=>!v)){document.getElementById("decisionFeedback").textContent="Choose all decision fields first.";return}
  let score=0;expected.forEach((v,i)=>{if(vals[i]===v)score++});a.note=document.getElementById("analystNotes").value.trim();const iso=new Date().toISOString();a.decision={classification:vals[0],severity:vals[1],action:vals[2],score,submittedAt:nowStamp(),submittedAtISO:iso};
  if(vals[2]==="Escalate to L2 / Incident Response"){a.status="Escalated";a.owner="SOC L2"}else if(vals[2]==="Close as False Positive"){a.status="Closed";a.owner="SOC L1"}else{a.status="In Progress";a.owner="SOC L1"}
  saveState();const fb=document.getElementById("decisionFeedback");fb.className="feedback "+(score===3?"good":"warn");fb.innerHTML=`<strong>Saved • Score: ${score}/3</strong><br>Expected: ${expected.map(escapeHTML).join(" • ")}<br>${score===3?"Correct L1 decision.":"Review the evidence and compare your reasoning."}`;const banner=document.getElementById("savedBanner");banner.classList.remove("hidden");banner.textContent=`✓ Investigation saved. Reopening this alert will keep your decision and notes.`;renderAll();
}

function populateAlertForm(){
  const sel=document.getElementById("newTemplate");sel.innerHTML=ALERT_TEMPLATES.map((t,i)=>`<option value="${i}">${escapeHTML(t.name)}</option>`).join("");fillAlertFormFromTemplate(0);
}
function fillAlertFormFromTemplate(index){const t=ALERT_TEMPLATES[index];document.getElementById("newName").value=t.name;document.getElementById("newSeverity").value=t.severity;document.getElementById("newMitre").value=t.mitre;document.getElementById("newSummary").value=t.summary;document.getElementById("newHost").value=rand(HOSTS);document.getElementById("newUser").value=rand(USERS);document.getElementById("newIp").value=rand(IPS)}
function showAlertModal(){populateAlertForm();document.getElementById("alertModal").classList.remove("hidden");document.getElementById("modalBackdrop").classList.remove("hidden");document.getElementById("newName").focus()}
function hideAlertModal(){document.getElementById("alertModal").classList.add("hidden");document.getElementById("modalBackdrop").classList.add("hidden")}
function addCustomAlert(e){
  e.preventDefault();const templateIndex=Number(document.getElementById("newTemplate").value),t=ALERT_TEMPLATES[templateIndex];const seq=state.alerts.reduce((m,a)=>{const n=parseInt(String(a.id).replace(/\D/g,""),10);return Number.isFinite(n)?Math.max(m,n):m},0)+1;
  const alert=normalizeAlert({id:`CUS-${String(seq).padStart(5,"0")}`,time:randomTime(),name:document.getElementById("newName").value.trim(),severity:document.getElementById("newSeverity").value,host:document.getElementById("newHost").value.trim(),user:document.getElementById("newUser").value.trim(),ip:document.getElementById("newIp").value.trim(),status:"New",owner:"Unassigned",mitre:document.getElementById("newMitre").value.trim(),templateIndex,summary:document.getElementById("newSummary").value.trim(),expectedSeverity:document.getElementById("newSeverity").value,custom:true,note:"",decision:null});
  state.alerts.unshift(alert);state.page=1;saveState();renderAll();hideAlertModal();switchView("alerts");openInvestigation(alert.id);
}

function exportProgress(){
  const payload={app:"SOC L1 Local Practice Lab",version:STORAGE_VERSION,exportedAt:new Date().toISOString(),alerts:state.alerts};const blob=new Blob([JSON.stringify(payload,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`soc-l1-progress-${new Date().toISOString().slice(0,10)}.json`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
}
function importProgress(file){
  const reader=new FileReader();reader.onload=()=>{try{const data=JSON.parse(String(reader.result));if(!data||!Array.isArray(data.alerts)||!data.alerts.length)throw new Error("No alerts found");state.alerts=data.alerts.map(normalizeAlert);state.page=1;saveState();renderAll();alert(`Imported ${state.alerts.length} alerts and saved investigation progress.`)}catch(err){alert("Could not import this progress file: "+err.message)}};reader.readAsText(file);
}
function resetLab(){if(!confirm("Reset the lab? This will delete saved local investigation progress and regenerate 560 sample alerts. Export your progress first if you want a backup."))return;try{localStorage.removeItem(STORAGE_KEY)}catch{}generateAlerts(560);switchView("overview")}

// UI events
document.querySelectorAll(".nav-item").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.view)));
document.querySelectorAll("[data-go-alerts]").forEach(b=>b.addEventListener("click",()=>switchView("alerts")));
document.getElementById("searchInput").addEventListener("input",()=>{state.page=1;renderAlerts()});
document.getElementById("severityFilter").addEventListener("change",()=>{state.page=1;renderAlerts()});
document.getElementById("statusFilter").addEventListener("change",()=>{state.page=1;renderAlerts()});
document.getElementById("prevPage").addEventListener("click",()=>{if(state.page>1){state.page--;renderAlerts()}});
document.getElementById("nextPage").addEventListener("click",()=>{const m=Math.ceil(getFiltered().length/state.pageSize);if(state.page<m){state.page++;renderAlerts()}});
document.getElementById("newCaseBtn").addEventListener("click",showAlertModal);
document.getElementById("closeModal").addEventListener("click",hideAlertModal);document.getElementById("cancelModal").addEventListener("click",hideAlertModal);document.getElementById("modalBackdrop").addEventListener("click",hideAlertModal);
document.getElementById("newTemplate").addEventListener("change",e=>fillAlertFormFromTemplate(Number(e.target.value)));document.getElementById("addAlertForm").addEventListener("submit",addCustomAlert);
document.getElementById("exportBtn").addEventListener("click",exportProgress);document.getElementById("importBtn").addEventListener("click",()=>document.getElementById("importFile").click());document.getElementById("importFile").addEventListener("change",e=>{if(e.target.files?.[0])importProgress(e.target.files[0]);e.target.value=""});document.getElementById("resetBtn").addEventListener("click",resetLab);
document.getElementById("closeDrawer").addEventListener("click",closeDrawer);document.getElementById("drawerBackdrop").addEventListener("click",closeDrawer);document.querySelectorAll("#drawerTabs .tab").forEach(b=>b.addEventListener("click",()=>activateDrawerTab(b.dataset.tab)));
document.addEventListener("keydown",e=>{if(e.key==="Escape"){closeDrawer();hideAlertModal()}});

if(!loadState())generateAlerts(560);else renderAll();
