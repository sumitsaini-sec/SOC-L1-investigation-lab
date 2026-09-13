import type { Investigation,GroundTruth,Worksheet,Feedback } from './types';

const COMMON = new Set(['this','that','with','from','into','then','than','were','was','are','the','and','for','has','have','had','not','but','its','their','there','record','event','observed','evidence','alert','activity','shows','showed','reviewed']);
const words=(s:string)=>(s.toLowerCase().match(/[\p{L}\p{N}_.:@\\/-]+/gu)||[]);
export function meaningful(s:string){
    const ws=words(s),unique=new Set(ws);
    return s.trim().length>=30&&ws.length>=8&&unique.size>=7&&!/(.)\1{9,}/u.test(s)&&Math.max(...[...unique].map(x=>ws.filter(w=>w===x).length))/Math.max(ws.length,1)<.45;
}
const has=(s:string,t:string)=>!!t&&s.toLowerCase().includes(t.toLowerCase());
const cited=(s:string,ids:string[])=>ids.filter(id=>has(s,id));
const usefulTerms=(s:string)=>[...new Set(words(s).filter(x=>x.length>=3&&!COMMON.has(x)))];
function findingQuality(s:string,f:{eventId:string;tokens:string[];observation:string;interpretation:string}){
    if(!meaningful(s)||!has(s,f.eventId))return 0;
    const tokenHits=new Set((f.tokens||[]).filter(x=>has(s,x))).size;
    const expected=usefulTerms(`${f.observation} ${f.interpretation}`).filter(x=>x.toLowerCase()!==f.eventId.toLowerCase());
    const factHits=expected.filter(x=>has(s,x)).length;
    if(tokenHits>=2&&factHits>=3)return 100;
    if(tokenHits>=2&&factHits>=1)return 85;
    if(tokenHits>=1&&factHits>=2)return 70;
    return 35;
}
function contradictions(w:Worksheet,t:GroundTruth){
    const out:string[]=[];
    const by=(area:string)=>t.findings.find(f=>f.area===area);
    const id=by('identity'),net=by('network'),ep=by('endpoint'),ctx=by('context'),email=by('email');
    if(id?.tokens?.some(x=>/^success$/i.test(x))&&/(?:no|without)\s+(?:any\s+)?successful\s+(?:authentication|logon|sign-in|session)/i.test(w.authenticationFindings))out.push('Identity notes deny a successful authentication that exists in the cited record.');
    if(net&&/\ballowed\b/i.test(`${net.observation} ${net.interpretation}`)&&/\b(?:blocked|denied|dropped)\b/i.test(w.networkFindings))out.push('Network notes say the connection was blocked/denied, but the referenced telemetry records an allowed connection.');
    if(net&&/\b(?:blocked|denied|dropped)\b/i.test(`${net.observation} ${net.interpretation}`)&&/\ballowed\b/i.test(w.networkFindings))out.push('Network notes say the connection was allowed, but the referenced telemetry records it as blocked/denied.');
    if(ep&&/(?:distinct|different).{0,40}(?:hash|digest)|(?:hash|digest).{0,40}(?:distinct|different)/i.test(`${ep.observation} ${ep.interpretation}`)&&/\b(?:same|identical)\s+(?:image\s+and\s+)?(?:artifact\s+)?(?:hash|digest)\b/i.test(w.endpointFindings)&&!/\b(?:not|different|distinct)\b/i.test(w.endpointFindings))out.push('Endpoint notes collapse distinct process-image and artifact hashes into the same file.');
    if(ctx?.effect==='contradicts_detection'&&/\b(?:no|without)\s+(?:approved|authorized|expected|change|maintenance)\b/i.test(w.notes))out.push('Context notes deny the qualifying/contradicting business context present in the cited evidence.');
    if(ctx?.effect==='limits_confidence'&&/\b(?:complete|no missing|no gap|fully observed|conclusive)\b/i.test(w.notes))out.push('Context notes claim complete/conclusive telemetry even though the scenario contains an evidence gap.');
    if(email&&/\bspf.{0,20}\bpass(?:ed)?\b/i.test(`${email.observation} ${email.interpretation}`)&&/\bspf.{0,20}\b(?:fail|failed)\b/i.test(w.evidenceReviewed))out.push('Email notes say SPF failed even though the cited authentication result passed.');
    if(email&&/\bspf.{0,20}\b(?:fail|failed)\b/i.test(`${email.observation} ${email.interpretation}`)&&/\bspf.{0,20}\bpass(?:ed)?\b/i.test(w.evidenceReviewed))out.push('Email notes say SPF passed even though the cited authentication result failed.');
    return out;
}

export function validate(w:Worksheet,bookmarks:string[]){
    if(!w.verdict||!w.disposition)throw Error('Choose a verdict and disposition.');
    if(!meaningful(w.observedActivity))throw Error('Describe specific observed facts; repeated characters or filler cannot be submitted.');
    if(!meaningful(w.evidenceReviewed)||bookmarks.length<2)throw Error('Bookmark at least two records and explain their observations.');
    if(cited(w.evidenceReviewed,bookmarks).length<2)throw Error('Evidence Reviewed must cite at least two of your bookmarked event IDs, not only generic/filler text.');
    if(!meaningful(w.scope)||!w.affectedAssets.trim())throw Error('Document supported scope and affected assets.');
    if(!meaningful(w.nextStep))throw Error('Give a specific next step, an owner and the evidence needed.');
    if((w.disposition.startsWith('Escalate')||w.disposition==='Containment Recommended')&&!meaningful(w.escalationReason))throw Error('Explain which evidence justifies escalation or containment.');
    if(w.verdict==='Needs More Investigation'&&w.disposition==='Close Alert')throw Error('An inconclusive investigation requires monitoring or escalation.');
    if(new Set([w.observedActivity,w.evidenceReviewed,w.scope,w.nextStep].map(s=>s.trim().toLowerCase())).size!==4)throw Error('Use distinct observations, evidence, scope and next steps rather than copying the same paragraph.');
}

export function score(i:Investigation,t:GroundTruth):Feedback{
    const w=i.worksheet,correct:string[]=[],missed:string[]=[],dimensions:Record<string,number>={},findings=t.findings||[];let total=0;
    const check=(name:string,p:number,weight:number,yes:string,no:string)=>{const bounded=Math.max(0,Math.min(100,p));dimensions[name]=Math.round(bounded);total+=bounded*weight/100;(bounded>=70?correct:missed).push(bounded>=70?yes:no);};
    const bestFinding=(s:string,area?:string)=>Math.max(0,...findings.filter(f=>!area||f.area===area).map(f=>findingQuality(s,f)));
    check('Verdict accuracy',w.verdict===t.verdict?100:0,25,'Your verdict matches the correlated evidence.',`Expected ${t.verdict}. ${t.reason}`);

    const required=t.requiredEvidence||[];
    const collected=required.filter(e=>i.bookmarks.includes(e)&&has(w.evidenceReviewed,e));
    const evidenceCoverage=required.length?Math.round(collected.length/required.length*100):100;
    check('Evidence collection',Math.min(100,collected.length/Math.max(1,Math.min(3,required.length))*100),15,'Key records are bookmarked and cited.','Bookmark and cite process, network and context records: '+required.join(', '));

    const analyses:[string,string,keyof Worksheet][]=[['IOC analysis','ioc','iocFindings'],['Endpoint investigation','endpoint','endpointFindings'],['Identity investigation','identity','authenticationFindings'],['Network analysis','network','networkFindings'],['Context and uncertainty','context','notes']];
    if(t.expectedAreas.includes('email'))analyses.push(['Email investigation','email','evidenceReviewed']);
    for(const [name,area,key] of analyses){
        const field=String(w[key]||''),f=findings.find(x=>x.area===area),dup=key!=='evidenceReviewed'&&analyses.some(x=>x[2]!==key&&String(w[x[2]]||'').trim().toLowerCase()===field.trim().toLowerCase());
        const reviewed=i.reviewed.includes(area==='context'?'timeline':area);
        const quality=reviewed&&!dup?bestFinding(field,area):0;
        check(name,quality,30/analyses.length,name+': specific observations and record references documented.',f?`${name}: cite ${f.eventId} and explain the observed facts (${f.observation}) rather than generic prose.`:name+': include actual observations and references.');
    }

    const scope=t.scope.every(h=>has(w.scope+' '+w.affectedAssets,h));
    const scopeCited=findings.some(f=>has(w.scope,f.eventId));
    check('Scope determination',scope&&meaningful(w.scope)&&scopeCited?100:scope?40:0,10,'Affected scope is tied to cited evidence.','Observed scope includes '+t.scope.join(', ')+'. Cite supporting records and qualify unconfirmed related activity.');

    const docs=[bestFinding(w.observedActivity)>=70,bestFinding(w.evidenceReviewed)>=70,bestFinding(w.notes)>=70,meaningful(w.nextStep)&&/L2|analyst|owner|team|response|administrator/i.test(w.nextStep)&&/collect|validate|confirm|acquire|review|request|monitor|contain|investigate|verify/i.test(w.nextStep)];
    check('Documentation quality',docs.filter(Boolean).length/4*100,10,'Handoff includes observations, record references and an assigned next action.','Use cited observations, actual record facts, uncertainty and an assigned next step. Length alone earns no documentation credit.');

    const closureQuality=bestFinding(w.notes,'context');
    const escalates=meaningful(w.escalationReason)&&findings.some(f=>has(w.escalationReason,f.eventId));
    const justified=t.dispositions.includes(w.disposition)&&(w.disposition==='Close Alert'?closureQuality>=70:escalates);
    check('Escalation decision',justified?100:0,10,'Disposition has an evidence-based rationale.','Expected '+t.dispositions.join(' / ')+'. Cite its supporting record in escalation or closure context.');

    const contradictionList=contradictions(w,t);
    if(contradictionList.length){for(const c of contradictionList)missed.push(c);total=Math.min(total,69);}
    if(bestFinding(w.evidenceReviewed)<70){missed.push('Evidence Reviewed cites records but does not accurately describe enough of their actual observations.');total=Math.min(total,89);}

    return{score:Math.round(total),groundTruth:t.verdict,difficulty:t.difficulty,reason:t.reason,correct,missed,dimensions,durationSeconds:Math.max(0,Math.round((Date.now()-Date.parse(i.started_at||new Date().toISOString()))/1000)),evidence:findings,contradictions:contradictionList,evidenceCoverage,rubricVersion:'3 · bookmarked evidence + observed-fact anchoring + contradiction checks'};
}
