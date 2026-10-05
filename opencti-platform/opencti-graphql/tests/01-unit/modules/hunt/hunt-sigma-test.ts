import { describe, expect, it } from 'vitest';
import { SIGMA_RULE_MAX_LENGTH, validateSigmaRule, wildcardMatches } from '../../../../src/modules/hunt/hunt-sigma';

describe('Sigma condition wildcards', () => {
  it('should match identifiers segment by segment like a glob', () => {
    expect(wildcardMatches('selection_*', 'selection_cmd')).toBe(true);
    expect(wildcardMatches('selection_*', 'filter_cmd')).toBe(false);
    expect(wildcardMatches('*_cmd', 'selection_cmd')).toBe(true);
    expect(wildcardMatches('s*_b', 'sel_b')).toBe(true);
    expect(wildcardMatches('s*_b', 'sel_a')).toBe(false);
    expect(wildcardMatches('a*b*c', 'axxbyyc')).toBe(true);
    expect(wildcardMatches('a*b*c', 'axxcyyb')).toBe(false);
    expect(wildcardMatches('ab*ba', 'aba')).toBe(false);
    expect(wildcardMatches('*', 'anything')).toBe(true);
    expect(wildcardMatches('sel', 'sel')).toBe(true);
    expect(wildcardMatches('sel', 'sel_a')).toBe(false);
    expect(wildcardMatches(`${'a*'.repeat(25)}z`, 'a'.repeat(60))).toBe(false);
  });
});

const VALID_RULE = `
title: Encoded PowerShell command line
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\\powershell.exe'
  selection_cli:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  filter_admin:
    User: 'svc-admin'
  condition: all of selection_* and not filter_admin
tags:
  - attack.execution
  - attack.t1059.001
  - attack.T1027
`;

describe('Hunt Sigma validation', () => {
  it('should accept a well-formed rule and extract its metadata', () => {
    const result = validateSigmaRule(VALID_RULE);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.title).toBe('Encoded PowerShell command line');
    expect(result.level).toBe('high');
    expect(result.logsource_product).toBe('windows');
    expect(result.logsource_category).toBe('process_creation');
    expect(result.logsource_service).toBeNull();
    expect(result.detection_fields).toEqual(['CommandLine', 'Image', 'User']);
    expect(result.attack_techniques).toEqual(['T1059.001', 'T1027']);
  });

  it('should refuse empty and oversized rules', () => {
    expect(validateSigmaRule('').valid).toBe(false);
    expect(validateSigmaRule(null).errors).toEqual(['The Sigma rule is empty']);
    const oversized = validateSigmaRule(`title: x\n${'#'.repeat(SIGMA_RULE_MAX_LENGTH)}`);
    expect(oversized.valid).toBe(false);
    expect(oversized.errors[0]).toContain(`${SIGMA_RULE_MAX_LENGTH}`);
  });

  it('should refuse several YAML documents, invalid YAML and non mapping documents', () => {
    expect(validateSigmaRule(`${VALID_RULE}\n---\n${VALID_RULE}`).errors).toEqual(['A hunt holds exactly one Sigma rule (one YAML document)']);
    expect(validateSigmaRule('title: [unclosed').valid).toBe(false);
    expect(validateSigmaRule('- a\n- b').errors).toEqual(['The Sigma rule must be a YAML mapping']);
  });

  it('should refuse YAML aliases (entity expansion)', () => {
    const rule = 'title: &t alias\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image: *t\n  condition: selection\n';
    const result = validateSigmaRule(rule);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('not valid YAML');
  });

  it('should report every structural error', () => {
    const result = validateSigmaRule('status: wrong\nlevel: extreme\nlogsource: {}\ndetection:\n  condition: selection\n');
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([
      'The Sigma rule must have a title',
      'The Sigma rule status must be one of stable, test, experimental, deprecated, unsupported',
      'The Sigma rule level must be one of informational, low, medium, high, critical',
      'The Sigma rule logsource must define a product, a category or a service',
      'The Sigma rule detection must define at least one search identifier',
      'The Sigma condition references an unknown search identifier: selection',
    ]);
  });

  it('should require a detection with a condition referencing known identifiers', () => {
    const missingDetection = validateSigmaRule('title: t\nlogsource:\n  product: linux\n');
    expect(missingDetection.errors).toEqual(['The Sigma rule must have a detection section']);
    const missingCondition = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  selection:\n    a: b\n');
    expect(missingCondition.errors).toEqual(['The Sigma rule detection must have a condition']);
    const wildcard = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  sel_a:\n    a: b\n  sel_b:\n    c: d\n  condition: 1 of sel_* or (s*_b)\n');
    expect(wildcard.valid).toBe(true);
    // Many wildcard segments against an identifier they do not match: answered at once, no backtracking
    const segments = `${'a*'.repeat(25)}z`;
    const slow = validateSigmaRule(`title: t\nlogsource:\n  product: linux\ndetection:\n  ${'a'.repeat(60)}:\n    a: b\n  condition: 1 of ${segments}\n`);
    expect(slow.valid).toBe(false);
    const quantified = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  sel_a:\n    a: b\n  sel_b:\n    c: d\n  sel_c:\n    e: f\n  condition: 2 of sel_* and not (10 of sel_c)\n');
    expect(quantified.errors).toEqual([]);
    const bareNumber = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  sel_a:\n    a: b\n  condition: sel_a and not 10\n');
    expect(bareNumber.valid).toBe(false);
    const unknown = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  sel_a:\n    a: b\n  condition: 2 of sel_* or missing\n');
    expect(unknown.valid).toBe(false);
    const scalarSearch = validateSigmaRule('title: t\nlogsource:\n  product: linux\ndetection:\n  selection: value\n  condition: selection\n');
    expect(scalarSearch.errors).toEqual(['The Sigma search identifier selection must be a map or a list']);
  });

  it('should accept keyword lists and ignore aggregation expressions', () => {
    const rule = 'title: t\nlogsource:\n  service: sshd\ndetection:\n  keywords:\n    - "Failed password"\n  condition: keywords | count() > 10\n';
    const result = validateSigmaRule(rule);
    expect(result.valid).toBe(true);
    expect(result.detection_fields).toEqual([]);
    expect(result.logsource_service).toBe('sshd');
  });
});
