import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import ts from 'typescript';

// Language has no dedicated UI. All other SDO screens must keep these integrations.
const screens = [
  'analyses/reports/Report', 'analyses/groupings/Grouping', 'analyses/notes/Note',
  'analyses/opinions/Opinion', 'analyses/malware_analyses/MalwareAnalysis',
  'analyses/security_coverages/SecurityCoverage',
  'arsenal/channels/Channel', 'arsenal/malwares/Malware', 'arsenal/tools/Tool',
  'arsenal/vulnerabilities/Vulnerability',
  'cases/case_incidents/CaseIncident', 'cases/case_rfis/CaseRfi', 'cases/case_rfts/CaseRft',
  'cases/feedbacks/Feedback', 'cases/tasks/Task',
  'entities/events/Event', 'entities/individuals/Individual', 'entities/organizations/Organization',
  'entities/sectors/Sector', 'entities/systems/System', 'entities/securityPlatforms/SecurityPlatform',
  'events/incidents/Incident', 'events/observed_data/ObservedData',
  'locations/administrative_areas/AdministrativeArea', 'locations/cities/City',
  'locations/countries/Country', 'locations/positions/Position', 'locations/regions/Region',
  'observations/indicators/Indicator', 'observations/infrastructures/Infrastructure',
  'techniques/attack_patterns/AttackPattern', 'techniques/courses_of_action/CourseOfAction',
  'techniques/data_components/DataComponent', 'techniques/data_sources/DataSource', 'techniques/narratives/Narrative',
  'threats/campaigns/Campaign', 'threats/intrusion_sets/IntrusionSet',
  'threats/threat_actors_group/ThreatActorGroup', 'threats/threat_actors_individual/ThreatActorIndividual',
];

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const source = (path: string) => readFileSync(resolve(root, path), 'utf8');

const sharedLocationScreens = new Set([
  'locations/administrative_areas/AdministrativeArea',
  'locations/cities/City',
  'locations/countries/Country',
  'locations/regions/Region',
]);

const detailsPath = (screen: string) => {
  if (sharedLocationScreens.has(screen)) return 'locations/LocationDetails.tsx';
  const prefix = `${screen}Details`;
  return `${prefix}.${existsSync(resolve(root, `${prefix}.tsx`)) ? 'tsx' : 'jsx'}`;
};

describe('SDO custom-field integration coverage', () => {
  it.each(screens)('%s uses generic custom fields in creation and edition', (screen) => {
    const creation = source(`${screen}${screen.endsWith('SecurityPlatform') ? 'CreationForm' : 'Creation'}.tsx`);
    expect(creation).toContain("from '@components/common/custom_fields/CustomFieldsFormik'");
    expect(creation).toContain('<CustomFieldValuesCreation');
    expect(creation).toContain('entityType=');
    expect(creation).toMatch(/getCustomFieldValues\(values\)|\.\.\.cleanedValues/);

    const prefix = `${screen}${screen.endsWith('/Task') ? 's' : ''}EditionOverview`;
    const edition = source(`${prefix}.${existsSync(resolve(root, `${prefix}.tsx`)) ? 'tsx' : 'jsx'}`);
    expect(edition).toContain('<CustomFieldValuesEdition');
    expect(edition).toMatch(/CustomFieldValuesEdition_values|customFieldValues\s*\{/);
    expect(edition).toContain('fieldPatch={editor.fieldPatch}');
  });

  it.each([
    'common/identities/IdentityCreation.jsx',
    'common/location/LocationCreation.tsx',
    'cases/tasks/CaseTaskCreation.tsx',
    'analyses/notes/StixCoreObjectOrStixCoreRelationshipNotesCards.tsx',
    'analyses/opinions/StixCoreObjectOpinionsRadarDialog.tsx',
  ])('covers contextual creation in %s', (path) => {
    const content = source(path);
    expect(content).toMatch(/from '@components\/common\/custom_fields\/(Dynamic)?CustomFieldsFormik'/);
    expect(content).toContain('<CustomFieldValuesCreation');
  });

  it.each(screens)('%s displays custom fields once inside its Details grid', (screen) => {
    const path = detailsPath(screen);
    const content = source(path);
    expect(content).toMatch(/values=\{\w+\.customFieldValues \?\? \[\]\}/);
    expect(content).not.toContain('<StixDomainObjectCustomFieldValues');

    const parsed = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const displays: ts.JsxSelfClosingElement[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isJsxSelfClosingElement(node) && node.tagName.getText(parsed) === 'CustomFieldValuesDisplay') displays.push(node);
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    expect(displays).toHaveLength(1);
    const parent = displays[0].parent;
    expect(ts.isJsxElement(parent)).toBe(true);
    if (ts.isJsxElement(parent)) {
      expect(parent.openingElement.tagName.getText(parsed)).toBe('Grid');
      expect(parent.openingElement.attributes.properties.some((attribute) => ts.isJsxAttribute(attribute) && attribute.name.getText(parsed) === 'container')).toBe(true);
    }

    // Position's entity data is supplied by the parent rather than its relationships fragment.
    const owner = screen.endsWith('/Position') ? source(`${screen}.tsx`) : content;
    expect(owner).toMatch(/customFieldValues\s*\{\s*\.\.\.CustomFieldValuesDisplay_values\s+@relay\(mask:\s*false\)/);
    if (sharedLocationScreens.has(screen)) {
      expect(source(`${screen}.tsx`)).toContain('...LocationDetails_location');
      expect(source(`${screen}.tsx`)).toContain('<LocationDetails');
    }
  });

  it('covers all dedicated SDO Details implementations', () => {
    expect(screens).toHaveLength(39);
    expect(new Set(screens.map(detailsPath)).size).toBe(36);
  });

  it('keeps graph edition but does not display custom fields in Basic information', () => {
    expect(source('common/stix_domain_objects/StixDomainObjectEditionOverview.jsx')).toContain('<CustomFieldValuesEdition');
    const overview = source('common/stix_domain_objects/StixDomainObjectOverview.jsx');
    expect(overview).not.toContain('StixDomainObjectCustomFieldValues');
    expect(overview).not.toContain('CustomFieldValuesDisplay');
  });
});

describe('STIX core relationship custom-field integration coverage', () => {
  const prefix = 'common/stix_core_relationships/StixCoreRelationship';

  it('uses the configured relationship type in the shared creation form', () => {
    const creation = source(`${prefix}CreationForm.jsx`);
    expect(creation).toContain("const STIX_CORE_RELATIONSHIP_TYPE = 'stix-core-relationship'");
    expect(creation).toMatch(/<CustomFieldsFormik\s+entityType=\{STIX_CORE_RELATIONSHIP_TYPE\}/);
    expect(creation).toContain('<CustomFieldValuesCreation />');
    const owner = source(`${prefix}Creation.tsx`);
    expect(owner).toContain('<StixCoreRelationshipCreationForm');
    expect(owner).toContain('...values,');
    expect(owner).toContain('customFieldValues?: CustomFieldValueAddInput[]');
  });

  it('loads stored values and preserves reference-enforced commits and inferred guards', () => {
    const edition = source(`${prefix}EditionOverview.tsx`);
    expect(edition).toMatch(/customFieldValues\s*\{\s*\.\.\.CustomFieldValuesDisplay_values\s+@relay\(mask:\s*false\)/);
    expect(edition).toMatch(/!stixCoreRelationship.is_inferred && \(\s*<CustomFieldValuesEdition/);
    expect(edition).toContain('entityType={stixCoreRelationshipType}');
    expect(edition).toContain('values={stixCoreRelationship.customFieldValues ?? []}');
    expect(edition).toContain('fieldPatch={editor.fieldPatch}');
    expect(edition).toContain('enableReferences={enableReferences}');
    expect(edition).toContain('...otherValues,');
    expect(edition).toContain('...StixCoreRelationshipOverview_stixCoreRelationship');
  });

  it('displays custom values exactly once inside the Details card grid', () => {
    const path = `${prefix}Overview.jsx`;
    const content = source(path);
    expect(content).toMatch(/customFieldValues\s*\{\s*\.\.\.CustomFieldValuesDisplay_values\s+@relay\(mask:\s*false\)/);
    const parsed = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const displays: ts.JsxSelfClosingElement[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isJsxSelfClosingElement(node) && node.tagName.getText(parsed) === 'CustomFieldValuesDisplay') displays.push(node);
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    expect(displays).toHaveLength(1);
    const display = displays[0];
    expect(display.getText(parsed)).toContain('entityType="stix-core-relationship"');
    expect(display.getText(parsed)).toContain('values={stixCoreRelationship.customFieldValues ?? []}');
    const grid = display.parent;
    expect(ts.isJsxElement(grid)).toBe(true);
    if (ts.isJsxElement(grid)) expect(grid.openingElement.tagName.getText(parsed)).toBe('Grid');
    const card = grid.parent;
    expect(ts.isJsxElement(card)).toBe(true);
    if (ts.isJsxElement(card)) expect(card.openingElement.getText(parsed)).toBe("<Card title={t('Details')}>");
  });
});
