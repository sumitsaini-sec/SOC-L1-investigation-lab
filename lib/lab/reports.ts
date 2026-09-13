import { worksheetFields } from './catalog';
import type { Alert,Investigation,LabEvent } from './types';
export const slaHours=(priority:string)=>priority==='Critical'?1:priority==='High'?4:priority==='Medium'?24:48;
export function handoff(a:Alert,i:Investigation){const w=i.worksheet;return `${a.id} · ${a.name}\nAttempt: ${i.attempt||1}\nSeverity: ${w.severity}\nUser: ${a.user}\nEndpoint: ${a.host}\nIncident: ${a.incident_id||'Standalone'}\nDetected: ${a.time}\nSource IP: ${a.source_ip}\nDomain: ${a.domain}\n\n${worksheetFields.map(([k,l])=>l+':\n'+w[k as keyof typeof w]).join('\n\n')}\n\nVerdict: ${w.verdict||'Pending'}\nDisposition: ${w.disposition||'Pending'}\nEvidence IDs:\n${i.bookmarks.join('\n')}`;}
const cell=(s:any)=>String(s??'').replaceAll('|','\\|').replaceAll('\n',' ');
export function markdownReport(a:Alert,i:Investigation,records:LabEvent[],c?:any,actions:any[]=[]){const w=i.worksheet;return `# ${cell(c?.id||a.id)} — ${cell(a.name)}

Synthetic SOC training case. All indicators and response actions are simulated.

| Field | Value |
| --- | --- |
${Object.entries({Alert:a.id,Case:c?.id||'Not created',Attempt:i.attempt||1,'Dataset version':a.datasetVersion||1,'Sequence profile':a.sequenceProfile||'n/a',Status:i.status,Severity:w.severity,Verdict:w.verdict||'Pending',Disposition:w.disposition||'Pending',Analyst:c?.assigned||'SOC Analyst L1',Detected:a.time,Submitted:i.submitted_at||'Not submitted',User:a.user,Endpoint:a.host,Domain:a.domain,'Artifact SHA256':a.hash,'Hints used':i.hintsUsed||0,'SLA policy':c?.slaPolicy||'from_case_creation','SLA hours':c?.slaHours||'n/a','SLA due':c?.due_at||'n/a'}).map(([k,v])=>`| ${k} | ${cell(v)} |`).join('\n')}

## Escalation summary

${w.escalationReason||'No escalation rationale recorded.'}

**Next step:** ${w.nextStep||'Pending'}

${worksheetFields.map(([k,l])=>`## ${l}\n\n${w[k as keyof typeof w]||'Not recorded.'}`).join('\n\n')}

## Preserved evidence

| Record | Time (UTC) | Source | Object role | Observation |
| --- | --- | --- | --- | --- |
${records.map(e=>`| ${cell(e.id)} | ${cell(e.timestamp)} | ${cell(e.source)} | ${cell(e.data?.objectRole||e.data?.artifactRole||e.kind)} | ${cell(e.message)} |`).join('\n')}

## Case notes

${c?.notes||'No additional case notes.'}

${Array.isArray(c?.slaHistory)&&c.slaHistory.length?`## SLA history\n\n${c.slaHistory.map((x:any)=>`- ${x.time}: ${x.from?`${x.from} → `:''}${x.priority}, ${x.hours}h, due ${x.due_at}. ${x.reason||''}`).join('\n')}\n\n`:''}## Simulated response log

${actions.map(x=>`- ${x.time}: **${x.action}** on ${x.target}. ${x.reason}`).join('\n')||'No response actions recorded.'}

${i.feedback?`## Assessment feedback

Score: **${i.feedback.score}/100**. Scenario verdict: **${i.feedback.groundTruth}**. Evidence coverage: **${i.feedback.evidenceCoverage??'n/a'}%**.

${i.feedback.reason}

### Evidence-by-conclusion

${(i.feedback.evidence||[]).map(f=>`- **${f.eventId}** (${f.role}${f.effect?`, ${f.effect}`:''}): ${f.observation} ${f.interpretation}`).join('\n')}

${i.feedback.contradictions?.length?`### Contradictions detected\n\n${i.feedback.contradictions.map(x=>`- ${x}`).join('\n')}\n\n`:''}`:''}## Raw evidence

${records.map(e=>`### ${e.id}\n\n\`\`\`\`json\n${JSON.stringify(e,null,2)}\n\`\`\`\``).join('\n\n')}
`;}
