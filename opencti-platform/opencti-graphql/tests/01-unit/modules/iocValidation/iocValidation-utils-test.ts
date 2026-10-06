import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  analyzeValidationPattern,
  extractIocFromIndicator,
  isDeploymentReporter,
  isIocValidationTestKind,
  isSummaryComplete,
  requestAccessEndsOf,
  requestAccessOf,
  requesterIdOf,
  resolveTestKind,
  summarizeValidationResults,
} from '../../../../src/modules/iocValidation/iocValidation-utils';
import { buildIocValidationRequestForOpenAEV } from '../../../../src/modules/iocValidation/iocValidation-converter';
import type { StoreEntityIocValidationRequest } from '../../../../src/modules/iocValidation/iocValidation-types';
import type { StixId } from '../../../../src/types/stix-2-1-common';

const ALL_KINDS = ['dns_resolution', 'network_traffic', 'http_head', 'file_drop', 'log_injection'] as const;

const indicator = (pattern: string, patternType = 'stix') => ({
  internal_id: 'internal-1',
  standard_id: 'indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11',
  pattern,
  pattern_type: patternType,
});

describe('resolveTestKind', () => {
  it('should map domains and hostnames to DNS resolution only', () => {
    expect(resolveTestKind({ type: 'Domain-Name', value: 'evil.example' }, ['dns_resolution'])).toEqual({ kind: 'dns_resolution', value: 'evil.example' });
    expect(resolveTestKind({ type: 'Hostname', value: 'host.evil.example' }, ['dns_resolution'])).toEqual({ kind: 'dns_resolution', value: 'host.evil.example' });
    expect(resolveTestKind({ type: 'Domain-Name', value: 'evil.example' }, ['network_traffic'])).toBeUndefined();
  });
  it('should map IP addresses to the safe network test only when allowed', () => {
    expect(resolveTestKind({ type: 'IPv4-Addr', value: '198.51.100.7' }, [...ALL_KINDS])).toEqual({ kind: 'network_traffic', value: '198.51.100.7' });
    expect(resolveTestKind({ type: 'IPv6-Addr', value: '2001:db8::1' }, ['dns_resolution'])).toBeUndefined();
  });
  it('should map URLs to HTTP HEAD only, never to a DNS resolution of their host', () => {
    expect(resolveTestKind({ type: 'Url', value: 'https://evil.example/path' }, [...ALL_KINDS])).toEqual({ kind: 'http_head', value: 'https://evil.example/path' });
    expect(resolveTestKind({ type: 'Url', value: 'https://evil.example/path' }, ['dns_resolution'])).toBeUndefined();
    expect(resolveTestKind({ type: 'Url', value: 'https://evil.example/path' }, ['file_drop'])).toBeUndefined();
  });
  it('should map files to the surrogate drop or the log injection', () => {
    const file = { type: 'StixFile', name: 'payload.exe', hashes: { 'SHA-256': 'abc' } };
    expect(resolveTestKind(file, [...ALL_KINDS])).toEqual({ kind: 'file_drop', value: 'payload.exe' });
    expect(resolveTestKind(file, ['log_injection'])).toEqual({ kind: 'log_injection', value: 'abc' });
    expect(resolveTestKind({ type: 'StixFile', hashes: { MD5: 'def' } }, ['file_drop'])).toBeUndefined();
  });
  it('should ignore unsupported observable types', () => {
    expect(resolveTestKind({ type: 'Email-Addr', value: 'a@b.c' }, [...ALL_KINDS])).toBeUndefined();
  });
  it('should validate test kinds', () => {
    expect(isIocValidationTestKind('dns_resolution')).toEqual(true);
    expect(isIocValidationTestKind('exploit')).toEqual(false);
  });
});

describe('extractIocFromIndicator', () => {
  it('should extract a domain IOC from a STIX pattern', () => {
    const extraction = extractIocFromIndicator(indicator("[domain-name:value = 'evil.example']"), ['dns_resolution']);
    expect(extraction.ioc).toEqual({
      indicator_id: 'internal-1',
      indicator_ref: 'indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11',
      observable_type: 'Domain-Name',
      value: 'evil.example',
      test_kind: 'dns_resolution',
      file_name: null,
      hashes: null,
    });
  });
  it('should merge file name and hashes of a file pattern', () => {
    const pattern = "[file:name = 'payload.exe' AND file:hashes.'SHA-256' = 'abc123']";
    const extraction = extractIocFromIndicator(indicator(pattern), ['log_injection']);
    expect(extraction.ioc?.test_kind).toEqual('log_injection');
    expect(extraction.ioc?.value).toEqual('abc123');
    expect(extraction.ioc?.file_name).toEqual('payload.exe');
    expect(extraction.ioc?.hashes).toEqual({ 'SHA-256': 'abc123' });
  });
  it('should only drop a file when a file AND pattern can be satisfied by the log injection', () => {
    const pattern = "[file:name = 'payload.exe' AND file:hashes.'SHA-256' = 'abc123']";
    expect(extractIocFromIndicator(indicator(pattern), ['file_drop']).reason).toEqual('No allowed test kind applies to this indicator');
  });
  it('should never test a value the indicator excludes or does not fully match', () => {
    const unsupported = 'Only patterns made of equality comparisons joined by OR, or on a single file, can be validated';
    expect(extractIocFromIndicator(indicator("[domain-name:value != 'allowed.example']"), ['dns_resolution']).reason).toEqual(unsupported);
    expect(extractIocFromIndicator(indicator("[domain-name:value = 'a.example' AND ipv4-addr:value = '198.51.100.7']"), [...ALL_KINDS]).reason).toEqual(unsupported);
    expect(extractIocFromIndicator(indicator("[domain-name:value = 'a.example'] FOLLOWEDBY [domain-name:value = 'b.example']"), ['dns_resolution']).reason).toEqual(unsupported);
    expect(extractIocFromIndicator(indicator("[domain-name:value MATCHES '^evil']"), ['dns_resolution']).reason).toEqual(unsupported);
    expect(extractIocFromIndicator(indicator("[domain-name:value = 'evil.example'] WITHIN 300 SECONDS"), ['dns_resolution']).reason).toEqual(unsupported);
  });
  it('should accept alternatives and ignore keywords inside values', () => {
    expect(analyzeValidationPattern("[domain-name:value = 'evil.example' OR domain-name:value = 'bad.example']")).toEqual({ supported: true, conjunctiveFile: false });
    expect(analyzeValidationPattern("[url:value = 'https://evil.example/?a=1&b=NOT IN']")).toEqual({ supported: true, conjunctiveFile: false });
    expect(analyzeValidationPattern("[file:name = 'a.exe' AND file:hashes.MD5 = 'b']")).toEqual({ supported: true, conjunctiveFile: true });
  });
  it('should explain why an indicator cannot be validated', () => {
    expect(extractIocFromIndicator(indicator('title: x', 'sigma'), ['dns_resolution']).reason).toEqual('Only STIX patterns can be validated');
    expect(extractIocFromIndicator(indicator("[ipv4-addr:value = '198.51.100.7']"), ['dns_resolution']).reason)
      .toEqual('No allowed test kind applies to this indicator');
  });
});

describe('summarizeValidationResults', () => {
  it('should count outcomes and pairs without answer', () => {
    const summary = summarizeValidationResults(5, 2, ['detected', 'prevented', 'missed', 'requested']);
    expect(summary).toEqual({ total: 5, requested: 2, detected: 1, prevented: 1, missed: 1, error: 0, skipped: 2 });
    expect(isSummaryComplete(summary)).toEqual(false);
  });
  it('should be complete when every pair is answered', () => {
    const summary = summarizeValidationResults(3, 0, ['detected', 'error', 'missed']);
    expect(summary).toEqual({ total: 3, requested: 0, detected: 1, prevented: 0, missed: 1, error: 1, skipped: 0 });
    expect(isSummaryComplete(summary)).toEqual(true);
  });
});

describe('buildIocValidationRequestForOpenAEV', () => {
  it('should build the contract object sent to OpenAEV', () => {
    const request = {
      internal_id: '5c7f0a2e-1111-4a2b-9c3d-123456789abc',
      name: 'Validation of 1 indicator(s) on 1 security platform(s)',
      test_kinds: ['dns_resolution'],
      created_at: '2026-10-03T10:00:00.000Z',
      updated_at: '2026-10-03T10:00:00.000Z',
    } as unknown as StoreEntityIocValidationRequest;
    const indicatorRef = 'indicator--3f6b4c1e-8f5e-4c43-9e52-0f8d5f0e5a11' as StixId;
    const platformRef = 'identity--7a0c2d4e-2222-4b3c-8d4e-abcdefabcdef' as StixId;
    const relationRef = 'relationship--9b1d3f5a-3333-4c4d-9e5f-fedcbafedcba' as StixId;
    const object = buildIocValidationRequestForOpenAEV(request, {
      requestedBy: 'admin',
      indicatorRefs: [indicatorRef],
      platformRefs: [platformRef],
      iocs: [{ indicator_id: 'internal-1', indicator_ref: indicatorRef, observable_type: 'Domain-Name', value: 'evil.example', test_kind: 'dns_resolution' }],
      pairs: [{ indicator_ref: indicatorRef, platform_ref: platformRef, deployed_on_ref: relationRef }],
    });
    expect(object.type).toEqual('x-opencti-ioc-validation-request');
    expect(object.id).toEqual('x-opencti-ioc-validation-request--5c7f0a2e-1111-4a2b-9c3d-123456789abc');
    expect(object.spec_version).toEqual('2.1');
    expect(object.requested_by).toEqual('admin');
    expect(object.iocs).toEqual([{ indicator_ref: indicatorRef, observable_type: 'Domain-Name', value: 'evil.example', test_kind: 'dns_resolution', file_name: null, hashes: null }]);
    expect(object.pairs).toEqual([{ indicator_ref: indicatorRef, platform_ref: platformRef, deployed_on_ref: relationRef }]);
    expect(object.extensions['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba']).toEqual({
      extension_type: 'new-sdo',
      id: '5c7f0a2e-1111-4a2b-9c3d-123456789abc',
      type: 'Ioc-Validation-Request',
    });
    expect(object.description).toBeUndefined();
  });
});

describe('IOC validation requester', () => {
  it('should be the first creator of the request', () => {
    expect(requesterIdOf({ creator_id: ['user-1', 'user-2'] })).toEqual('user-1');
    expect(requesterIdOf({ creator_id: 'user-3' })).toEqual('user-3');
  });

  it('should be undefined when the request has no creator', () => {
    expect(requesterIdOf({ creator_id: [] })).toBeUndefined();
    expect(requesterIdOf({ creator_id: null })).toBeUndefined();
    expect(requesterIdOf({ creator_id: ['', 'user-4'] })).toEqual('user-4');
    expect(requesterIdOf({})).toBeUndefined();
  });
});

describe('IOC validation request access', () => {
  it('should carry the markings of every indicator and security platform', () => {
    const access = requestAccessOf([
      { 'object-marking': ['tlp-amber'] },
      { 'object-marking': ['tlp-amber', 'pap-red'] },
      { 'object-marking': null },
    ]);
    expect(access.markingIds.sort()).toEqual(['pap-red', 'tlp-amber']);
  });

  it('should be shared with the organizations all its ends are shared with only', () => {
    expect(requestAccessOf([
      { granted: ['org-a', 'org-b'] },
      { granted: ['org-b', 'org-c'] },
      { granted: ['org-b', 'org-a'] },
    ]).organizationIds).toEqual(['org-b']);
    // An end shared with no organization leaves the request to the platform organization
    expect(requestAccessOf([{ granted: ['org-a'] }, { granted: [] }]).organizationIds).toEqual([]);
    expect(requestAccessOf([{ granted: ['org-a'] }, {}]).organizationIds).toEqual([]);
    expect(requestAccessOf([]).organizationIds).toEqual([]);
  });

  it('should never be loosened by an indicator or security platform that can no longer be read', () => {
    const request = { 'object-marking': ['tlp-red'], granted: ['org-a'] };
    const surviving = [{ 'object-marking': ['tlp-green'], granted: ['org-a', 'org-b'] }];
    const access = requestAccessOf(requestAccessEndsOf(request, surviving, 2));
    expect(access.markingIds.sort()).toEqual(['tlp-green', 'tlp-red']);
    expect(access.organizationIds).toEqual(['org-a']);
    // Every end read: the access follows the ends only
    expect(requestAccessOf(requestAccessEndsOf(request, surviving, 1))).toEqual({ markingIds: ['tlp-green'], organizationIds: ['org-a', 'org-b'] });
  });
});

describe('IOC validation result reporter', () => {
  it('should be one of the accounts that recorded the deployment', () => {
    expect(isDeploymentReporter({ creator_id: ['splunk-account', 'openaev-account'] }, 'splunk-account')).toEqual(true);
    expect(isDeploymentReporter({ creator_id: ['splunk-account', 'openaev-account'] }, 'openaev-account')).toEqual(true);
    expect(isDeploymentReporter({ creator_id: 'splunk-account' }, 'splunk-account')).toEqual(true);
  });

  it('should reject any other account', () => {
    expect(isDeploymentReporter({ creator_id: ['splunk-account'] }, 'analyst-account')).toEqual(false);
    expect(isDeploymentReporter({ creator_id: [] }, 'analyst-account')).toEqual(false);
    expect(isDeploymentReporter({ creator_id: null }, 'analyst-account')).toEqual(false);
    expect(isDeploymentReporter({}, 'analyst-account')).toEqual(false);
  });
});
