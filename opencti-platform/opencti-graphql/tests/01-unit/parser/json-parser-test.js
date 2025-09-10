import { describe, expect, it } from 'vitest';
import jsonMappingExecution from '../../../src/parser/json-mapper';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { cisa_data, cisa_mapper } from './json-mapper-cisa';
import { trino_data, trino_mapper } from './json-mapper-trino';
import { misp_data, misp_mapper } from './json-mapper-misp';
import { STIX_EXT_OCTI_SCO } from '../../../src/types/stix-2-1-extensions';

const buildMaps = (stixBundle) => {
  const mapById = new Map();
  const mapByType = new Map();
  const mapByFromAndTo = new Map();
  for (let index = 0; index < stixBundle.objects.length; index += 1) {
    const element = stixBundle.objects[index];
    mapById.set(element.id, element);
    if (element.type === 'relationship') {
      mapByFromAndTo.set(`${element.source_ref}-${element.target_ref}`, element);
    }
    if (mapByType.has(element.type)) {
      const vals = mapByType.get(element.type);
      vals.push(element);
      mapByType.set(element.type, vals);
    } else {
      mapByType.set(element.type, [element]);
    }
  }
  return { mapById, mapByType, mapByFromAndTo };
};

describe('JSON mapper testing', () => {
  it('should cisa correctly parsed', async () => {
    const stixBundle = await jsonMappingExecution(testContext, ADMIN_USER, cisa_data, cisa_mapper);
    const { mapById, mapByType, mapByFromAndTo } = buildMaps(stixBundle);
    expect(stixBundle.objects.length).toBe(3556);
    expect(mapByType.get('marking-definition').length).toBe(1);
    expect(mapByType.get('identity').length).toBe(1);
    expect(mapByType.get('software').length).toBe(528);
    expect(mapByType.get('vulnerability').length).toBe(1249);
    expect(mapByType.get('relationship').length).toBe(1777);
    // Test software binding
    const software = mapById.get('software--bd1130d6-ada7-594b-b54f-c0db8c814978');
    expect(software.name).toBe('Windows');
    expect(software.vendor).toBe('Microsoft');
    // Test vulnerability binding
    const vulnerability = mapById.get('vulnerability--4c64fad0-de31-5fdb-ad73-34beff2c3943');
    expect(vulnerability.name).toBe('CVE-2025-21335');
    expect(vulnerability.description).toBe('Microsoft Windows Hyper-V NT Kernel Integration VSP contains a use-after-free vulnerability that allows a local attacker to gain SYSTEM privileges.');
    expect(vulnerability.created_by_ref).toBe('identity--80f07246-1c8c-5225-9ac5-fba6d6345f99');
    expect(vulnerability.object_marking_refs[0]).toBe('marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9');
    // Test relationship binding
    const relationship = mapByFromAndTo.get(`${software.id}-${vulnerability.id}`);
    expect(relationship).not.toBeNull();
  });
  it('should trino correctly parsed', async () => {
    const stixBundle = await jsonMappingExecution(testContext, ADMIN_USER, trino_data, trino_mapper);
    const { mapById, mapByType } = buildMaps(stixBundle);
    expect(mapByType.get('identity').length).toBe(40);
    // Test organization binding
    const organization = mapById.get('identity--c8b81eb7-706a-5ec5-a0a0-804064556134');
    expect(organization.name).toBe('c6f0e1718c2140b348432e9b00000019');
    expect(organization.identity_class).toBe('organization');
  });
  it('should misp correctly parsed', async () => {
    const stixBundle = await jsonMappingExecution(testContext, ADMIN_USER, misp_data, misp_mapper, { externalUri: 'http://localhost' });
    const { mapById, mapByType } = buildMaps(stixBundle);
    expect(mapByType.get('marking-definition').length).toBe(1);
    expect(mapByType.get('location').length).toBe(1);
    expect(mapByType.get('identity').length).toBe(1);
    expect(mapByType.get('external-reference').length).toBe(83);
    expect(mapByType.get('domain-name').length).toBe(2);
    expect(mapByType.get('intrusion-set').length).toBe(2);
    expect(mapByType.get('malware').length).toBe(2);
    expect(mapByType.get('file').length).toBe(12);
    expect(mapByType.get('indicator').length).toBe(58);
    expect(mapByType.get('ipv4-addr').length).toBe(44);
    expect(mapByType.get('note').length).toBe(2);
    expect(mapByType.get('report').length).toBe(1);
    expect(mapByType.get('relationship').length).toBe(523);
    // Test external reference binding
    const externalReference = mapById.get('external-reference--42ed5840-451b-55e0-8b34-fcb2eb773bf3');
    expect(externalReference.source_name).toBe('External analysis');
    expect(externalReference.external_id).toBe('335bd77b-81c4-4720-94f6-bf672b62d092');
    expect(externalReference.url).toBe('https://www.microsoft.com/en-us/security/blog/2024/12/04/frequent-freeloader-part-i-secret-blizzard-compromising-storm-0156-infrastructure-for-espionage');
    // Test domain binding
    const domain = mapById.get('domain-name--07f3ac51-335f-524c-918f-86f80da2bce3');
    expect(domain.value).toBe('hostelhotels.net');
    // Test intrusion-set binding
    const intrusionSet = mapById.get('intrusion-set--62b3f3f6-d0c0-546b-a153-ac278a822794');
    expect(intrusionSet.name).toBe('Secret Blizzard');
    expect(intrusionSet.aliases).toStrictEqual(['KRYPTON', 'Venomous Bear', 'Turla', 'Snake']);
    // Test malware binding
    const malware = mapById.get('malware--497fe074-67e0-5640-b7a5-af2e36a5e1db');
    expect(malware.name).toBe('TinyTurla');
    expect(malware.description).toBe('Talos describes this as a malware family with very scoped functionality and thus a small code footprint, likely used as a second chance backdoor.');
    expect(malware.is_family).toBeTruthy();
    // Test file binding
    const file = mapById.get('file--1b6bb8bc-bc12-5fe7-9d5c-43fce2a4ac84');
    expect(file.object_marking_refs[0]).toBe('marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9');
    expect(file.hashes['SHA-256']).toBe('aba8b59281faa8c1c43a4ca7af075edd3e3516d3cef058a1f43b093177b8f83c');
    expect(file.extensions[STIX_EXT_OCTI_SCO].description).toBe('CrimsonRAT SHA-256 (lustsorelfar.exe) - Storm-0156');
    expect(file.extensions[STIX_EXT_OCTI_SCO].score).toBe(290);
    // Test report binding
    const report = mapById.get('report--589c20b9-e5c9-5239-99e8-01a1bc0529e0');
    expect(report.object_marking_refs[0]).toBe('marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9');
    expect(report.external_references.length).toBe(83);
    expect(report.external_references[0].source_name).toBe('External analysis');
    expect(report.external_references[0].url).toBe('https://www.microsoft.com/en-us/security/blog/2024/12/04/frequent-freeloader-part-i-secret-blizzard-compromising-storm-0156-infrastructure-for-espionage/');
    expect(report.external_references[0].external_id).toBe('335bd77b-81c4-4720-94f6-bf672b62d092');
    expect(report.name).toBe('Secret Blizzard compromising Storm-0156 infrastructure for espionage / Snowblind: The Invisible Hand of Secret Blizzard');
    expect(report.report_types).toStrictEqual(['misp-event']);
    expect(report.object_refs.length).toBe(121);
  });
});
