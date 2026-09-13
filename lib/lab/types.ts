export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type Verdict = 'True Positive' | 'False Positive' | 'Benign Positive' | 'Needs More Investigation';
export type Family = 'Identity' | 'Email' | 'Malware' | 'Endpoint' | 'Lateral movement' | 'Network' | 'Web' | 'Privilege' | 'Cloud' | 'Insider';
export type Kind = 'auth' | 'process' | 'network' | 'dns' | 'email' | 'file' | 'registry' | 'service' | 'task' | 'context' | 'cloud';
export interface Rule {
    id: string;
    name: string;
    family: Family;
    technique: string;
    tactic: string;
    source: string;
    logic: string;
    description: string;
}
export interface LabUser {
    id: string;
    fullName: string;
    department: string;
    role: string;
    manager: string;
    normalCountry: string;
    normalHours: string;
    normalHost: string;
    email: string;
    groups: string[];
    risk: number;
}
export interface Host {
    id: string;
    user: string;
    os: string;
    ip: string;
    mac: string;
    department: string;
    type: string;
    lastSeen: string;
    edrStatus: string;
    risk: number;
}
export interface Alert {
    datasetVersion?: number;
    supersedes?: string;
    priorExerciseIds?: string[];
    sequenceProfile?: string;
    id: string;
    incident_id: string | null;
    name: string;
    category: string;
    family: Family;
    severity: Severity;
    status: string;
    time: string;
    firstSeen: string;
    lastSeen: string;
    source: string;
    rule_id: string;
    technique: string;
    tactic: string;
    user: string;
    host: string;
    source_ip: string;
    destination_ip: string;
    country: string;
    asn: string;
    domain: string;
    url: string;
    file: string;
    hash: string;
    process_name: string;
    summary: string;
}
export interface LabEvent {
    id: string;
    alert_id: string;
    incident_id: string | null;
    timestamp: string;
    kind: Kind;
    source: string;
    event_id: number;
    user: string;
    host: string;
    source_ip: string;
    destination_ip: string;
    domain: string;
    hash: string;
    process_name: string;
    message: string;
    severity: Severity;
    data: Record<string, any>;
}
export interface IOC {
    value: string;
    type: string;
    observations: Record<string, any>;
}
export interface GroundTruth {
    verdict: Verdict;
    difficulty: string;
    reason: string;
    expectedAreas: string[];
    scope: string[];
    requiredEvidence: string[];
    dispositions: string[];
    findings?: {area: string; eventId: string; tokens: string[]; observation: string; interpretation: string; role: "supporting" | "qualifying" | "contradicting"; effect?: "supports_verdict" | "qualifies_conclusion" | "contradicts_detection" | "limits_confidence"}[];
}
export interface Scenario {
    alert: Alert;
    events: LabEvent[];
    iocs: IOC[];
    truth: GroundTruth;
}
export interface Worksheet {
    observedActivity: string;
    evidenceReviewed: string;
    iocFindings: string;
    endpointFindings: string;
    authenticationFindings: string;
    networkFindings: string;
    scope: string;
    affectedAssets: string;
    actionTaken: string;
    escalationReason: string;
    nextStep: string;
    notes: string;
    verdict: Verdict | '';
    severity: Severity;
    disposition: string;
}
export interface Feedback {
    evidence?: GroundTruth["findings"];
    rubricVersion?: string;
    score: number;
    groundTruth: Verdict;
    difficulty: string;
    reason: string;
    correct: string[];
    missed: string[];
    dimensions: Record<string, number>;
    durationSeconds: number;
    contradictions?: string[];
    evidenceCoverage?: number;
}
export interface Investigation {
    attempt?: number;
    worksheetVersion?: number;
    revision?: number;
    hintsUsed?: number;
    bookmarkStoreVersion?: number;
    alert_id: string;
    status: string;
    started_at: string;
    updated_at: string;
    submitted_at: string | null;
    worksheet: Worksheet;
    reviewed: string[];
    bookmarks: string[];
    feedback: Feedback | null;
}
export const emptyWorksheet: Worksheet = { observedActivity: '', evidenceReviewed: '', iocFindings: '', endpointFindings: '', authenticationFindings: '', networkFindings: '', scope: '', affectedAssets: '', actionTaken: '', escalationReason: '', nextStep: '', notes: '', verdict: '', severity: 'Medium', disposition: '' };
