import { describe, expect, it } from 'vitest';
import {
  detectIocType,
  extractStixPatternValues,
  hasHuntIocLogic,
  iocKey,
  iocValuesOfElement,
  isDisclosableByHunt,
  normalizeHuntIocValues,
  normalizeIocValue,
} from '../../../../src/modules/hunt/hunt-iocs';
import { HUNT_MESSAGES, listNames, renderHuntMessage } from '../../../../src/modules/hunt/hunt-messages';
import { huntLogicError } from '../../../../src/modules/hunt/hunt-validators';
import type { BasicStoreEntityMarkingDefinition } from '../../../../src/types/store';

const marking = (id: string, definitionType: string, order: number) => {
  return { id, internal_id: id, definition_type: definitionType, x_opencti_order: order } as unknown as BasicStoreEntityMarkingDefinition;
};
const MARKINGS = new Map<string, BasicStoreEntityMarkingDefinition>([
  ['tlp-green', marking('tlp-green', 'TLP', 2)],
  ['tlp-amber', marking('tlp-amber', 'TLP', 3)],
  ['tlp-red', marking('tlp-red', 'TLP', 4)],
  ['pap-red', marking('pap-red', 'PAP', 4)],
]);

describe('Indicator hunt values', () => {
  it('should normalize each observable type and refuse invalid values', () => {
    expect(normalizeIocValue('IPv4-Addr', ' 198.51.100.7 ')?.value).toBe('198.51.100.7');
    expect(normalizeIocValue('IPv4-Addr', '198.51.100.300')).toBeNull();
    expect(normalizeIocValue('IPv6-Addr', '2001:DB8::1')?.value).toBe('2001:db8::1');
    expect(normalizeIocValue('Domain-Name', 'Evil.Example.COM.')?.value).toBe('evil.example.com');
    expect(normalizeIocValue('Domain-Name', 'not a domain')).toBeNull();
    expect(normalizeIocValue('Url', 'https://evil.example.com/Payload.exe')?.value).toBe('https://evil.example.com/Payload.exe');
    expect(normalizeIocValue('Url', 'evil.example.com')).toBeNull();
    expect(normalizeIocValue('Email-Addr', 'Phisher@Evil.Example.com')?.value).toBe('phisher@evil.example.com');
    expect(normalizeIocValue('Mac-Addr', '00-1A-2B-3C-4D-5E')?.value).toBe('00:1a:2b:3c:4d:5e');
    expect(normalizeIocValue('StixFile', 'D41D8CD98F00B204E9800998ECF8427E')).toEqual({ observable_type: 'StixFile', hash_algorithm: 'MD5', value: 'd41d8cd98f00b204e9800998ecf8427e' });
    // A hash whose length does not match its algorithm is not a value of that algorithm
    expect(normalizeIocValue('StixFile', 'd41d8cd98f00b204e9800998ecf8427e', 'SHA-256')).toBeNull();
    expect(normalizeIocValue('Software', 'anything')).toBeNull();
  });

  it('should detect the type of pasted values', () => {
    expect(detectIocType('203.0.113.9')).toBe('IPv4-Addr');
    expect(detectIocType('2001:db8::2')).toBe('IPv6-Addr');
    expect(detectIocType('https://evil.example.com/a')).toBe('Url');
    expect(detectIocType('phisher@evil.example.com')).toBe('Email-Addr');
    expect(detectIocType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe('StixFile');
    expect(detectIocType('evil.example.com')).toBe('Domain-Name');
    expect(detectIocType('just words')).toBeNull();
  });

  it('should read the equality comparisons of a STIX pattern only', () => {
    const values = extractStixPatternValues("[ipv4-addr:value = '198.51.100.7' OR domain-name:value = 'evil.example.com'] AND [file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']");
    expect(values.map((value) => `${value.observable_type}:${value.value}`)).toEqual([
      'IPv4-Addr:198.51.100.7',
      'Domain-Name:evil.example.com',
      'StixFile:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    ]);
    expect(extractStixPatternValues("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")[0].hash_algorithm).toBe('MD5');
    expect(extractStixPatternValues("[url:value = 'https://evil.example.com/it\\'s']")[0].value).toBe("https://evil.example.com/it's");
    // Other operators and properties have no value a lookup can search
    expect(extractStixPatternValues("[ipv4-addr:value ISSUBSET '198.51.100.0/24']")).toEqual([]);
    expect(extractStixPatternValues("[process:name = 'cmd.exe']")).toEqual([]);
  });

  it('should take the values of indicators and observables', () => {
    const element = (fields: Record<string, unknown>) => ({ internal_id: 'x', standard_id: 'x', entity_type: 'Indicator', ...fields }) as any;
    expect(iocValuesOfElement(element({ pattern_type: 'stix', pattern: "[ipv4-addr:value = '198.51.100.7']" }))).toHaveLength(1);
    expect(iocValuesOfElement(element({ pattern_type: 'sigma', pattern: 'title: x' }))).toEqual([]);
    const file = iocValuesOfElement(element({ entity_type: 'StixFile', hashes: { MD5: 'd41d8cd98f00b204e9800998ecf8427e', 'SHA-256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } }));
    expect(file.map((value) => value.hash_algorithm)).toEqual(['MD5', 'SHA-256']);
    expect(iocValuesOfElement(element({ entity_type: 'Domain-Name', value: 'Evil.Example.com' }))[0].value).toBe('evil.example.com');
    expect(iocValuesOfElement(element({ entity_type: 'Software', value: 'x' }))).toEqual([]);
  });

  it('should normalize, deduplicate and refuse pasted values', () => {
    expect(normalizeHuntIocValues([
      { observable_type: 'Domain-Name', value: 'Evil.Example.com' },
      { observable_type: 'Domain-Name', value: 'evil.example.com' },
      { observable_type: 'IPv4-Addr', value: '198.51.100.7' },
    ])).toEqual([{ observable_type: 'Domain-Name', value: 'evil.example.com' }, { observable_type: 'IPv4-Addr', value: '198.51.100.7' }]);
    expect(() => normalizeHuntIocValues([{ observable_type: 'IPv4-Addr', value: 'evil.example.com' }])).toThrow('Pasted value 1 is not a valid IPv4-Addr');
    expect(() => normalizeHuntIocValues(['{"observable_type": "IPv4-Addr"'])).toThrow('Pasted value 1 must be a JSON object with an observable type and a value');
    expect(normalizeHuntIocValues(null)).toEqual([]);
    expect(iocKey({ observable_type: 'IPv4-Addr', hash_algorithm: null, value: '198.51.100.7' })).toHaveLength(24);
  });

  it('should hunt an indicator only when every reader of the hunt can read it', () => {
    const amberHunt = { 'object-marking': ['tlp-amber'] };
    expect(isDisclosableByHunt(amberHunt, { 'object-marking': ['tlp-green'] }, MARKINGS)).toBe(true);
    expect(isDisclosableByHunt(amberHunt, { 'object-marking': ['tlp-amber'] }, MARKINGS)).toBe(true);
    expect(isDisclosableByHunt(amberHunt, { 'object-marking': ['tlp-red'] }, MARKINGS)).toBe(false);
    // A marking of a type the hunt does not carry is never covered
    expect(isDisclosableByHunt(amberHunt, { 'object-marking': ['pap-red'] }, MARKINGS)).toBe(false);
    expect(isDisclosableByHunt({}, {}, MARKINGS)).toBe(true);
    // Organizations: the readers of the hunt must all belong to an organization the element is shared with
    expect(isDisclosableByHunt({}, { granted: ['org-a'] }, MARKINGS)).toBe(false);
    expect(isDisclosableByHunt({ granted: ['org-a'] }, { granted: ['org-a', 'org-b'] }, MARKINGS)).toBe(true);
    expect(isDisclosableByHunt({ granted: ['org-a', 'org-c'] }, { granted: ['org-a'] }, MARKINGS)).toBe(false);
  });

  it('should know whether an indicator hunt has something to look for', () => {
    expect(hasHuntIocLogic({})).toBe(false);
    expect(hasHuntIocLogic({ hunt_ioc_values: [{ observable_type: 'IPv4-Addr', value: '198.51.100.7' }] })).toBe(true);
    expect(hasHuntIocLogic({ 'hunt-source': ['indicator-id'] })).toBe(true);
    expect(hasHuntIocLogic({ huntSources: ['report-id'] })).toBe(true);
    expect(hasHuntIocLogic({ hunt_ioc_filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }) })).toBe(false);
    expect(hasHuntIocLogic({ hunt_ioc_filters: JSON.stringify({ mode: 'and', filters: [{ key: ['objectLabel'], values: ['apt28'] }], filterGroups: [] }) })).toBe(true);
    expect(huntLogicError({ hunt_type: 'indicators' })?.message).toBe(HUNT_MESSAGES.logicIndicatorsMissing);
    expect(huntLogicError({ hunt_type: 'indicators', hunt_ioc_values: [{ observable_type: 'IPv4-Addr', value: '198.51.100.7' }] })).toBeNull();
  });
});

describe('Hunt readiness sentences', () => {
  it('should fill the placeholders of a sentence and keep the unknown ones', () => {
    expect(renderHuntMessage(HUNT_MESSAGES.iocCount, { count: 12 })).toBe('12 values to look for');
    expect(renderHuntMessage(HUNT_MESSAGES.sigmaInvalid, {})).toBe('Invalid Sigma rule: {errors}');
    expect(huntLogicError({ hunt_type: 'telemetry' })?.message).toBe('Add a Sigma rule or a native query');
    expect(huntLogicError({ hunt_type: 'infrastructure' })?.message).toBe('Add a native query for the internet platform');
  });

  it('should list at most three names', () => {
    expect(listNames(['Splunk', 'Splunk', 'Sentinel'])).toBe('Splunk, Sentinel');
    expect(listNames(['a', 'b', 'c', 'd', 'e'])).toBe('a, b, c +2');
  });
});
