// Demo data of the generic intelligence requirements proof of concept (feature flag INTELLIGENCE_REQUIREMENTS).
// Creates the knowledge and the four requirements of the mockup, then waits for the engine and prints a summary.
//
// Usage (dev platform running with the flag enabled):
//   node intelligence-requirements-demo-seed.mjs            baseline: knowledge + the four requirements
//   node intelligence-requirements-demo-seed.mjs --evolve   new facts, to watch the inbox react live
//
// Replayable: entities are found or created by name, the four [DEMO] requirements are deleted and recreated,
// and the facts changed by --evolve are reset (Akira no longer targets Europe, Citrix is not in CISA KEV).
// The token is read from opencti-graphql/config/development.json (or OPENCTI_TOKEN).
import { readFileSync } from 'node:fs';

const URL = process.env.OPENCTI_URL ?? 'http://localhost:4000/graphql';
const TOKEN = process.env.OPENCTI_TOKEN
  ?? JSON.parse(readFileSync(new globalThis.URL('../opencti-graphql/config/development.json', import.meta.url))).app.admin.token;
const EVOLVE = process.argv.includes('--evolve');
const PREFIX = '[DEMO]';

const gql = async (query, variables = {}) => {
  const res = await fetch(URL, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ query, variables }) });
  const json = await res.json();
  if (json.errors) throw new Error(`${json.errors[0].message} in ${query.slice(0, 90)}`);
  return json.data;
};
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

// region find or create
const find = async (listQuery, name, types) => {
  const typesArg = types ? ', types: $types' : '';
  const typesVar = types ? ', $types: [String]' : '';
  const data = await gql(`query($s: String${typesVar}) { ${listQuery}(search: $s, first: 50${typesArg}) { edges { node { id representative { main } } } } }`, { s: name, types });
  const node = data[listQuery].edges.map((e) => e.node).find((n) => n.representative?.main === name);
  return node?.id ?? null;
};
const sdo = async (listQuery, mutation, name, extra = {}) => {
  const existing = await find(listQuery, name);
  if (existing) return existing;
  const inputType = `${mutation[0].toUpperCase()}${mutation.slice(1)}AddInput`;
  const data = await gql(`mutation($input: ${inputType}!) { ${mutation}Add(input: $input) { id } }`, { input: { name, ...extra } });
  return data[`${mutation}Add`].id;
};
const software = async (name) => {
  const existing = await find('stixCyberObservables', name, ['Software']);
  if (existing) return existing;
  return (await gql('mutation($v: SoftwareAddInput) { stixCyberObservableAdd(type: "Software", Software: $v) { id } }', { v: { name } })).stixCyberObservableAdd.id;
};
const rel = async (fromId, relationship_type, toId, confidence = 75) => gql(
  'mutation($input: StixCoreRelationshipAddInput!) { stixCoreRelationshipAdd(input: $input) { id } }',
  { input: { fromId, toId, relationship_type, confidence } },
);
const deleteRelations = async (fromId, relationship_type, toId) => {
  const data = await gql('query($f: [String], $t: [String], $r: [String]) { stixCoreRelationships(fromId: $f, toId: $t, relationship_type: $r, first: 20) { edges { node { id } } } }', { f: [fromId], t: [toId], r: [relationship_type] });
  for (const e of data.stixCoreRelationships.edges) {
    await gql('mutation($id: ID!) { stixCoreRelationshipEdit(id: $id) { delete } }', { id: e.node.id });
  }
};
const patch = async (mutation, id, key, value) => gql(`mutation($id: ID!, $i: [EditInput]!) { ${mutation}(id: $id) { fieldPatch(input: $i) { id } } }`, { id, i: [{ key, value: [value] }] });
const report = async (name, description, objects) => {
  const existing = await find('reports', name);
  if (existing) return existing;
  return (await gql('mutation($input: ReportAddInput!) { reportAdd(input: $input) { id } }', { input: { name, description, published: new Date().toISOString(), objects } })).reportAdd.id;
};
// endregion

// region requirement helpers
const f = (key, value, operator = 'eq') => ({ key: [key], values: [String(value)], operator, mode: 'or' });
const filters = (...items) => ({ mode: 'and', filterGroups: [], filters: items });
const list = (id, name, role, entity_ids) => ({ id, name, kind: 'list', role, entity_ids });
const keywords = (id, name, values) => ({ id, name, kind: 'keywords', role: 'entry', keywords: values });
const graph = (id, name, from, relationship_types, direction, target_types, mode = 'auto', extra = {}) => ({
  id, name, kind: 'graph', from_group_ids: from, relationship_types, direction, target_types, mode, ...extra,
});
const rule = (id, name, points, extra = {}) => ({ id, name, points, ...extra });
// endregion

// 1. Knowledge
console.log('Creating the knowledge...');
const sectorFinance = await sdo('sectors', 'sector', 'Financial services');
const sectorAir = await sdo('sectors', 'sector', 'Air transportation');
const europe = await sdo('regions', 'region', 'Europe');
const northAmerica = await sdo('regions', 'region', 'North America');
// actors and their tooling
const fin7 = await sdo('intrusionSets', 'intrusionSet', 'FIN7');
const spider = await sdo('intrusionSets', 'intrusionSet', 'Scattered Spider');
const basta = await sdo('intrusionSets', 'intrusionSet', 'Black Basta');
const ta505 = await sdo('intrusionSets', 'intrusionSet', 'TA505');
const storm = await sdo('intrusionSets', 'intrusionSet', 'Storm-1811', { confidence: 55 });
const teamtnt = await sdo('intrusionSets', 'intrusionSet', 'TeamTNT');
const magecart = await sdo('intrusionSets', 'intrusionSet', 'Magecart Group 12');
const lumma = await sdo('malwares', 'malware', 'Lumma Stealer', { is_family: true });
const systembc = await sdo('malwares', 'malware', 'SystemBC', { is_family: true });
const systembc5 = await sdo('malwares', 'malware', 'SystemBC v5', { is_family: false, confidence: 55 });
const lockbit = await sdo('malwares', 'malware', 'LockBit', { is_family: true, malware_types: ['ransomware'] });
const akira = await sdo('malwares', 'malware', 'Akira', { is_family: true, malware_types: ['ransomware'] });
const qilin = await sdo('malwares', 'malware', 'Qilin', { is_family: true, malware_types: ['ransomware'] });
const qakbot = await sdo('malwares', 'malware', 'Qakbot', { is_family: true });
const kinsing = await sdo('malwares', 'malware', 'Kinsing', { is_family: true });
const rhadamanthys = await sdo('malwares', 'malware', 'Rhadamanthys', { is_family: true });
const cobalt = await sdo('tools', 'tool', 'Cobalt Strike');
const webshell = await sdo('tools', 'tool', 'PHPShell (web shell)');
const t1621 = await sdo('attackPatterns', 'attackPattern', 'MFA Request Generation', { x_mitre_id: 'T1621' });
// vulnerabilities
const vuln = (name, description, attributes) => sdo('vulnerabilities', 'vulnerability', name, { description, ...attributes });
const vForti = await vuln('CVE-2026-21412', 'FortiOS SSL-VPN heap overflow', { x_opencti_cisa_kev: true, x_opencti_epss_score: 0.94, x_opencti_cvss_base_score: 9.8, x_opencti_ssvc_exploitation: 'active' });
const vSap = await vuln('CVE-2025-31324', 'SAP NetWeaver unauthenticated upload', { x_opencti_cisa_kev: true, x_opencti_epss_score: 0.45, x_opencti_cvss_base_score: 10, x_opencti_ssvc_exploitation: 'active' });
const vCitrix = await vuln('CVE-2026-17890', 'Citrix ADC memory overread', { x_opencti_cisa_kev: false, x_opencti_epss_score: 0.62, x_opencti_cvss_base_score: 9.1, x_opencti_ssvc_exploitation: 'proof_of_concept' });
const vVeeam = await vuln('CVE-2026-29001', 'Veeam Backup deserialization', { x_opencti_cisa_kev: true, x_opencti_epss_score: 0.3, x_opencti_cvss_base_score: 9.8, x_opencti_ssvc_exploitation: 'active' });
const vIvanti = await vuln('CVE-2026-35110', 'Ivanti Connect Secure authentication bypass', { x_opencti_cisa_kev: true, x_opencti_epss_score: 0.88, x_opencti_cvss_base_score: 9.6, x_opencti_ssvc_exploitation: 'active' });
const vPhpAuth = await vuln('CVE-2026-33102', 'PHPShell 2.x authentication bypass', { x_opencti_cisa_kev: true, x_opencti_epss_score: 0.71, x_opencti_cvss_base_score: 9.8, x_opencti_ssvc_exploitation: 'active' });
const vPhpPath = await vuln('CVE-2026-28740', 'PHPShell 2.x path traversal', { x_opencti_cisa_kev: false, x_opencti_epss_score: 0.2, x_opencti_cvss_base_score: 7.5, x_opencti_ssvc_exploitation: 'proof_of_concept' });
const vPhpXss = await vuln('CVE-2025-11893', 'PHPShell stored XSS', { x_opencti_cisa_kev: false, x_opencti_epss_score: 0.01, x_opencti_cvss_base_score: 5.4, x_opencti_ssvc_exploitation: 'none' });
const vAltea = await vuln('CVE-2026-40417', 'Altea web services information disclosure', { x_opencti_cisa_kev: false, x_opencti_epss_score: 0.05, x_opencti_cvss_base_score: 6.5, x_opencti_ssvc_exploitation: 'none' });
// software, vendors and systems
const phpshell = await software('PHPShell 2.x');
const alteaWs = await software('Altea Web Services');
const amadeus = await sdo('organizations', 'organization', 'Amadeus');
const sabre = await sdo('organizations', 'organization', 'Sabre');
const navitaire = await sdo('organizations', 'organization', 'Navitaire');
const newSkies = await sdo('systems', 'system', 'Navitaire New Skies');
const altea = await sdo('systems', 'system', 'Amadeus Altea');
const pnrCampaign = await sdo('campaigns', 'campaign', 'PNR scraping via compromised travel-agent accounts');
const webshellCampaign = await sdo('campaigns', 'campaign', 'Mass web shell uploads on shared hosting');
const navitaireIncident = await sdo('incidents', 'incident', 'Navitaire New Skies data exposure', { confidence: 80 });

// Ransomware are found by their malware type (dynamic subject group), not listed one by one
for (const id of [lockbit, akira, qilin]) await patch('malwareEdit', id, 'malware_types', 'ransomware');
// Reset the facts changed by --evolve, so that the baseline is replayable
await deleteRelations(akira, 'targets', europe);
await patch('vulnerabilityEdit', vCitrix, 'x_opencti_cisa_kev', 'false');
console.log('Knowledge ready');

// 2. The four requirements (recreated: the engine replays the facts of the last days)
const existing = await gql('query { intelligenceRequirements(first: 200) { edges { node { id name } } } }');
for (const e of existing.intelligenceRequirements.edges) {
  if (e.node.name.startsWith(PREFIX) || e.node.name.startsWith('[POC]')) {
    await gql('mutation($id: ID!) { intelligenceRequirementDelete(id: $id) }', { id: e.node.id });
  }
}
const addRequirement = async (input) => (await gql('mutation($i: IntelligenceRequirementInput!) { intelligenceRequirementAdd(input: $i) { id name } }', { i: { ir_rescan_days: 7, ir_thresholds: [50, 80], ...input } })).intelligenceRequirementAdd;
const kev = filters(f('x_opencti_cisa_kev', 'true'));
const lowConfidence = rule('r-lowconf', 'Weak sourcing', -15, { filters: filters(f('confidence', 59, 'lte')) });

const requirements = [];
requirements.push(await addRequirement({
  name: `${PREFIX} Tracked threat actors against European financial services`,
  ir_question: 'Which new malware, tools, techniques and exploited vulnerabilities are our tracked actors adopting, and are they moving towards European banks?',
  ir_priority: 'critical',
  ir_subject_groups: [list('g-actors', 'Tracked actors', 'entry', [fin7, spider, basta, ta505]), list('g-context', 'Context', 'context', [sectorFinance, europe])],
  ir_scope_criteria: [
    graph('c1', 'Malware or tool used by a tracked actor', ['g-actors'], ['uses'], 'outgoing', ['Malware', 'Tool']),
    graph('c2', 'Technique used by a tracked actor', ['g-actors'], ['uses'], 'outgoing', ['Attack-Pattern']),
    graph('c3', 'Vulnerability targeted by a tracked actor', ['g-actors'], ['targets'], 'outgoing', ['Vulnerability']),
    graph('c4', 'Vulnerability exploited by their malware (2nd hop)', [], ['exploits'], 'outgoing', ['Vulnerability'], 'auto', { from_in_requirement: true }),
    graph('c5', 'Variant of a malware in the requirement', [], ['variant-of'], 'incoming', ['Malware'], 'propose', { from_in_requirement: true }),
    graph('c6', 'Intrusion set related to a tracked actor', ['g-actors'], ['related-to', 'part-of', 'derived-from'], 'both', ['Intrusion-Set'], 'propose'),
  ],
  ir_kiqs: [
    { id: 'kiq-1', text: 'What new malware or tools do tracked actors adopt?', criteria_ids: ['c1'] },
    { id: 'kiq-2', text: 'Which vulnerabilities do they exploit?', criteria_ids: ['c3', 'c4'] },
    { id: 'kiq-3', text: 'Which new techniques are attributed to them?', criteria_ids: ['c2'] },
  ],
  ir_relevance_rules: [
    rule('r-finance', 'Used by an actor targeting financial services', 30, { applies_to_types: ['Malware', 'Tool', 'Attack-Pattern'], path_condition: { relationship_types: ['uses'], direction: 'incoming', target_relationship_type: 'targets', target_ids: [sectorFinance] } }),
    rule('r-europe', 'Used by an actor targeting Europe', 15, { applies_to_types: ['Malware', 'Tool', 'Attack-Pattern'], path_condition: { relationship_types: ['uses'], direction: 'incoming', target_relationship_type: 'targets', target_ids: [europe] } }),
    rule('r-kev', 'Vulnerability in CISA KEV', 50, { applies_to_types: ['Vulnerability'], filters: kev }),
    rule('r-epss', 'Likely to be exploited', 10, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_epss_score', 0.5, 'gte')) }),
    rule('r-active', 'Actively exploited', 20, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_ssvc_exploitation', 'active')) }),
    rule('r-variant', 'Variants are less certain', -10, { applies_to_types: ['Malware'], applies_to_criterion_id: 'c5' }),
    lowConfidence,
  ],
}));
requirements.push(await addRequirement({
  name: `${PREFIX} PHPShell: vulnerabilities, exploitation and abuse`,
  ir_question: 'What vulnerabilities affect PHPShell, who exploits them, and is PHPShell being used as a web shell in intrusions?',
  ir_priority: 'high',
  ir_subject_groups: [list('g-product', 'Product', 'entry', [phpshell, webshell]), keywords('g-keywords', 'Keywords', ['phpshell', 'php shell'])],
  ir_scope_criteria: [
    graph('c1', 'Vulnerabilities of the product', ['g-product'], ['has'], 'outgoing', ['Vulnerability']),
    graph('c2', 'Threats exploiting these vulnerabilities (2nd hop)', [], ['exploits'], 'incoming', ['Malware', 'Intrusion-Set', 'Campaign'], 'auto', { from_in_requirement: true }),
    graph('c3', 'Threats using the web shell', ['g-product'], ['uses'], 'incoming', ['Intrusion-Set', 'Threat-Actor-Group', 'Campaign']),
    { id: 'c4', name: 'Keywords in reports', kind: 'keywords', from_group_ids: ['g-keywords'], target_types: ['Campaign', 'Malware', 'Intrusion-Set'], mode: 'propose' },
  ],
  ir_kiqs: [
    { id: 'kiq-1', text: 'Which vulnerabilities affect PHPShell?', criteria_ids: ['c1'] },
    { id: 'kiq-2', text: 'Who exploits them?', criteria_ids: ['c2'] },
    { id: 'kiq-3', text: 'Is the PHPShell web shell used in intrusions?', criteria_ids: ['c3'] },
  ],
  ir_relevance_rules: [
    rule('r-kev', 'In CISA KEV', 20, { applies_to_types: ['Vulnerability'], filters: kev }),
    rule('r-exploit', 'Public exploit available', 15, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_ssvc_exploitation', 'none', 'not_eq')) }),
    rule('r-cvss', 'Critical severity', 10, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_cvss_base_score', 9, 'gte')) }),
    rule('r-exploiting', 'Threat exploiting PHPShell vulnerabilities', 40, { applies_to_criterion_id: 'c2' }),
    rule('r-using', 'Threat using the web shell', 40, { applies_to_criterion_id: 'c3' }),
    lowConfidence,
  ],
}));
requirements.push(await addRequirement({
  name: `${PREFIX} Threats against airline reservation systems`,
  ir_question: 'Are there cyber threats targeting airline reservation systems?',
  ir_priority: 'medium',
  ir_subject_groups: [
    list('g-vendors', 'Vendors', 'both', [amadeus, sabre, navitaire]),
    list('g-systems', 'Systems', 'both', [newSkies, altea]),
    list('g-software', 'PSS software', 'entry', [alteaWs]),
    list('g-sector', 'Sector', 'both', [sectorAir]),
    keywords('g-keywords', 'Keywords', ['passenger service system', 'reservation system', 'pnr']),
  ],
  ir_scope_criteria: [
    graph('c1', 'Threats targeting a vendor or a system', ['g-vendors', 'g-systems'], ['targets'], 'incoming', ['Intrusion-Set', 'Malware', 'Campaign']),
    graph('c2', 'Incidents at a vendor', ['g-vendors'], ['targets'], 'incoming', ['Incident']),
    graph('c3', 'Vulnerabilities of PSS software', ['g-software'], ['has'], 'outgoing', ['Vulnerability']),
    graph('c4', 'Threats targeting the aviation sector', ['g-sector'], ['targets'], 'incoming', ['Intrusion-Set', 'Campaign'], 'propose'),
    { id: 'c5', name: 'Keywords in reports', kind: 'keywords', from_group_ids: ['g-keywords'], target_types: ['Malware', 'Intrusion-Set', 'Campaign', 'Incident'], mode: 'propose' },
  ],
  ir_kiqs: [
    { id: 'kiq-1', text: 'Are reservation systems or their vendors directly targeted?', criteria_ids: ['c1'] },
    { id: 'kiq-2', text: 'Have PSS vendors suffered confirmed incidents?', criteria_ids: ['c2'] },
    { id: 'kiq-3', text: 'Are there exploitable vulnerabilities in PSS software?', criteria_ids: ['c3'] },
    { id: 'kiq-4', text: 'Which actors target the aviation sector broadly?', criteria_ids: ['c4'] },
  ],
  ir_relevance_rules: [
    rule('r-direct', 'Directly targets a reservation system or vendor', 60, { applies_to_criterion_id: 'c1' }),
    rule('r-incident', 'Confirmed incident at a vendor', 50, { applies_to_criterion_id: 'c2' }),
    rule('r-sector', 'Targets the aviation sector', 25, { applies_to_criterion_id: 'c4' }),
    rule('r-keyword', 'Found through keywords', 10, { applies_to_criterion_id: 'c5' }),
    rule('r-kev', 'In CISA KEV', 20, { applies_to_types: ['Vulnerability'], filters: kev }),
    lowConfidence,
  ],
}));
requirements.push(await addRequirement({
  name: `${PREFIX} Exploitable vulnerabilities used by ransomware against Europe`,
  ir_question: 'Which vulnerabilities are exploited by ransomware operations targeting Europe, and which must we prioritise based on CVSS, EPSS, active exploitation, proof-of-concept availability and internet exposure?',
  ir_priority: 'critical',
  ir_subject_groups: [
    { id: 'g-ransomware', name: 'Ransomware', kind: 'filter', role: 'entry', filters: filters(f('entity_type', 'Malware'), f('malware_types', 'ransomware')) },
    list('g-region', 'Region', 'context', [europe]), keywords('g-keywords', 'Keywords', ['fortios', 'ssl-vpn'])],
  ir_scope_criteria: [
    graph('c1', 'Ransomware exploits vulnerability', ['g-ransomware'], ['exploits'], 'outgoing', ['Vulnerability']),
    { id: 'c2', name: 'Critical vulnerabilities (0 hop)', kind: 'attribute', target_types: ['Vulnerability'], target_filters: filters(f('x_opencti_cisa_kev', 'true'), f('x_opencti_cvss_base_score', 9.5, 'gte'), f('x_opencti_ssvc_exploitation', 'active')), mode: 'propose' },
    { id: 'c3', name: 'Keywords in reports', kind: 'keywords', from_group_ids: ['g-keywords'], target_types: ['Vulnerability'], mode: 'propose' },
    graph('c4', 'Other threats exploiting these vulnerabilities (2nd hop)', [], ['exploits', 'targets'], 'incoming', ['Intrusion-Set', 'Malware'], 'propose', { from_in_requirement: true }),
  ],
  ir_kiqs: [
    { id: 'kiq-1', text: 'Which vulnerabilities do ransomware operations targeting Europe exploit?', criteria_ids: ['c1'] },
    { id: 'kiq-2', text: 'Which critical, actively exploited vulnerabilities are not yet linked to ransomware?', criteria_ids: ['c2'] },
    { id: 'kiq-3', text: 'Which affect our internet-facing assets?', criteria_ids: [] },
  ],
  ir_relevance_rules: [
    rule('r-europe', 'Exploited by a threat targeting Europe', 0, { applies_to_types: ['Vulnerability'], applies_to_criterion_id: 'c1', required: true, path_condition: { relationship_types: ['exploits'], direction: 'incoming', target_relationship_type: 'targets', target_ids: [europe] } }),
    rule('r-kev', 'In CISA KEV', 30, { applies_to_types: ['Vulnerability'], filters: kev }),
    rule('r-active', 'Actively exploited', 25, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_ssvc_exploitation', 'active')) }),
    rule('r-poc', 'Proof of concept available', 15, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_ssvc_exploitation', 'proof_of_concept')) }),
    rule('r-epss', 'Likely to be exploited', 15, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_epss_score', 0.5, 'gte')) }),
    rule('r-cvss', 'Critical severity', 10, { applies_to_types: ['Vulnerability'], filters: filters(f('x_opencti_cvss_base_score', 9, 'gte')) }),
  ],
}));
console.log(`Requirements created: ${requirements.map((r) => r.name).join(' | ')}`);

// 3. Facts (relationships and reports). Already existing ones are upserted.
await rel(spider, 'uses', lumma, 80);
await rel(fin7, 'uses', lumma, 75);
await rel(fin7, 'uses', cobalt, 85);
await rel(basta, 'uses', cobalt, 80);
await rel(basta, 'uses', systembc, 75);
await rel(spider, 'uses', t1621, 75);
await rel(basta, 'targets', vForti, 75);
await rel(systembc, 'exploits', vSap, 70);
await rel(systembc5, 'variant-of', systembc, 55);
await rel(storm, 'part-of', basta, 55);
await rel(spider, 'targets', sectorFinance, 80);
await rel(fin7, 'targets', sectorFinance, 85);
await rel(fin7, 'targets', europe, 80);
await rel(basta, 'targets', europe, 75);
await rel(phpshell, 'has', vPhpAuth, 90);
await rel(phpshell, 'has', vPhpPath, 85);
await rel(phpshell, 'has', vPhpXss, 80);
await rel(kinsing, 'exploits', vPhpAuth, 80);
await rel(teamtnt, 'uses', webshell, 75);
await rel(pnrCampaign, 'targets', newSkies, 75);
await rel(navitaireIncident, 'targets', navitaire, 80);
await rel(spider, 'targets', sectorAir, 80);
await rel(magecart, 'targets', sectorAir, 70);
await rel(alteaWs, 'has', vAltea, 80);
await rel(lockbit, 'exploits', vForti, 85);
await rel(akira, 'exploits', vCitrix, 70);
await rel(akira, 'exploits', vVeeam, 80);
await rel(lockbit, 'targets', europe, 85);
await rel(akira, 'targets', northAmerica, 80);
await rel(qilin, 'exploits', vSap, 75);
await rel(qilin, 'targets', europe, 80);
await rel(qakbot, 'exploits', vForti, 70);
await rel(spider, 'targets', vForti, 75);
await report('FortiOS SSL-VPN exploitation wave', 'Several actors exploit FortiOS SSL-VPN appliances.', [vForti, vIvanti]);
await report('Sucuri: mass PHPShell uploads on shared hosting', 'Attackers upload phpshell variants on shared hosting providers.', [webshellCampaign]);
await report('Group-IB: travel-agent credentials sold for PNR access', 'Stolen credentials give access to PNR data of several airlines.', [lumma, pnrCampaign]);
console.log('Facts created');

if (EVOLVE) {
  await sleep(15000);
  await rel(akira, 'targets', europe, 80); // path condition: Citrix and Veeam meet the required rule again
  await patch('vulnerabilityEdit', vCitrix, 'x_opencti_cisa_kev', 'true'); // attribute change: score threshold
  await rel(spider, 'uses', rhadamanthys, 70); // scope: a new malware for a tracked actor
  console.log('New facts: Akira targets Europe, Citrix enters CISA KEV, Scattered Spider uses Rhadamanthys');
}

// 4. Wait for the engine and print a summary
console.log('Waiting for the engine (about 40s)...');
await sleep(40000);
for (const ir of requirements) {
  const data = await gql(`query($id: ID!) {
    intelligenceRequirementMatches(id: $id, first: 500) { edges { node { match_status match_excluded } } }
    intelligenceRequirementItems(id: $id, first: 500, statuses: [open]) { edges { node { item_kind } } }
  }`, { id: ir.id });
  const matches = data.intelligenceRequirementMatches.edges.map((e) => e.node);
  const items = data.intelligenceRequirementItems.edges.map((e) => e.node);
  const inRequirement = matches.filter((m) => ['auto', 'accepted'].includes(m.match_status) && !m.match_excluded).length;
  const proposed = matches.filter((m) => m.match_status === 'proposed').length;
  const excluded = matches.filter((m) => m.match_excluded).length;
  console.log(`- ${ir.name}: ${inRequirement} entities, ${proposed} proposed, ${excluded} excluded · inbox: ${items.length} to review`);
}
