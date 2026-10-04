import { describe, expect, it } from 'vitest';
import {
  bestTrigramMatch,
  buildPairFingerprint,
  buildProposalFingerprint,
  buildTfIdfVectors,
  canonicalizeEntityNames,
  canonicalizeName,
  combineEvidence,
  expandLeetVariants,
  getTaxonomyFamily,
  isInAmbiguousBand,
  jaccard,
  sparseCosine,
  topSharedTerms,
  trigramSimilarity,
} from '../../../../src/modules/curation/curation-normalization';
import type { CurationEvidence } from '../../../../src/modules/curation/curation-types';

const item = (score: number, weight: number): CurationEvidence => ({ evidence_type: 'test', score, weight, description: 'test' });

describe('Curation normalization', () => {
  it('should map entity types to taxonomy families', () => {
    expect(getTaxonomyFamily('Intrusion-Set')).toBe('actor');
    expect(getTaxonomyFamily('Threat-Actor-Group')).toBe('actor');
    expect(getTaxonomyFamily('Malware')).toBe('software');
    expect(getTaxonomyFamily('Tool')).toBe('software');
    expect(getTaxonomyFamily('Campaign')).toBe('campaign');
    expect(getTaxonomyFamily('Sector')).toBeUndefined();
  });

  it('should expand digits used as letters only between letters', () => {
    expect(expandLeetVariants('cl0p')).toEqual(['clop']);
    expect(expandLeetVariants('b1ackcat')).toEqual(['biackcat', 'blackcat']);
    expect(expandLeetVariants('apt28')).toEqual(['apt28']);
    expect(expandLeetVariants('lockbit30')).toEqual(['lockbit30']);
  });

  it('should give the same canonical form to vendor spellings of the same name', () => {
    expect([...canonicalizeName('Cl0p', 'Malware').full]).toContain('clop');
    expect([...canonicalizeName('CLOP', 'Malware').full]).toContain('clop');
    expect([...canonicalizeName('B1ackCat', 'Malware').full]).toContain('blackcat');
    expect([...canonicalizeName('Sofacy-Group', 'Intrusion-Set').full]).toContain('sofacygroup');
    expect([...canonicalizeName('Sofacy-Group', 'Intrusion-Set').stripped]).toContain('sofacy');
    expect([...canonicalizeName('Clop Ransomware (ELF)', 'Malware').stripped]).toContain('clop');
    expect([...canonicalizeName('Énergétique Bear', 'Intrusion-Set').full]).toContain('energetiquebear');
  });

  it('should keep versions and numbering significant', () => {
    expect([...canonicalizeName('LockBit 3.0', 'Malware').full]).toEqual(['lockbit30']);
    expect([...canonicalizeName('LockBit 2.0', 'Malware').full]).toEqual(['lockbit20']);
    expect([...canonicalizeName('APT28', 'Intrusion-Set').full]).toEqual(['apt28']);
  });

  it('should ignore too short or numeric canonical forms', () => {
    expect(canonicalizeName('AB', 'Malware').full.size).toBe(0);
    expect(canonicalizeName('1234', 'Malware').full.size).toBe(0);
    expect(canonicalizeName('', 'Malware').full.size).toBe(0);
  });

  it('should collect canonical forms of a name and its aliases without overlap', () => {
    const forms = canonicalizeEntityNames(['Team TNT', 'TeamTNT'], 'Intrusion-Set');
    expect(forms.full.has('teamtnt')).toBe(true);
    expect(forms.stripped.has('teamtnt')).toBe(false);
  });

  it('should compute trigram similarity with pg_trgm semantics', () => {
    expect(trigramSimilarity('Lazarus', 'Lazarus')).toBe(1);
    expect(trigramSimilarity('Lazarus Group', 'Lazarous Group')).toBeGreaterThan(0.5);
    expect(trigramSimilarity('Lazarus', 'Turla')).toBeLessThan(0.2);
    expect(trigramSimilarity('', 'Turla')).toBe(0);
  });

  it('should find the best trigram match ignoring short names', () => {
    const best = bestTrigramMatch(['APT', 'Charming Kitten'], ['Charming Kiten', 'CK']);
    expect(best?.left).toBe('Charming Kitten');
    expect(best?.right).toBe('Charming Kiten');
    expect(bestTrigramMatch(['APT'], ['CK'])).toBeUndefined();
  });

  it('should compute jaccard over sets and arrays', () => {
    expect(jaccard(['a', 'b'], ['b', 'c'])).toBeCloseTo(1 / 3);
    expect(jaccard(new Set<string>(), new Set<string>())).toBe(0);
  });

  it('should combine positive evidence with a noisy-OR and discount negative evidence', () => {
    expect(combineEvidence([item(1, 0.5), item(1, 0.5)])).toBe(0.75);
    expect(combineEvidence([item(1, 0.92)])).toBe(0.92);
    expect(combineEvidence([item(1, 0.8), item(1, -0.5)])).toBe(0.4);
    expect(combineEvidence([item(1, -0.5)])).toBe(0);
    expect(combineEvidence([])).toBe(0);
  });

  it('should evaluate the ambiguous band as half-open', () => {
    expect(isInAmbiguousBand(0.55, 0.55, 0.85)).toBe(true);
    expect(isInAmbiguousBand(0.85, 0.55, 0.85)).toBe(false);
    expect(isInAmbiguousBand(0.4, 0.55, 0.85)).toBe(false);
  });

  it('should build order-insensitive fingerprints', () => {
    expect(buildProposalFingerprint('merge', ['a', 'b'])).toBe(buildProposalFingerprint('merge', ['b', 'a']));
    expect(buildProposalFingerprint('merge', ['a', 'b'])).not.toBe(buildProposalFingerprint('alias', ['a', 'b']));
    expect(buildPairFingerprint(['x', 'y'])).toBe(buildPairFingerprint(['y', 'x']));
    expect(buildProposalFingerprint('merge', ['a', 'b'])).toHaveLength(64);
  });

  it('should compute TF-IDF cosine similarity and shared salient terms', () => {
    const vectors = buildTfIdfVectors([
      { id: 'a', text: 'Ransomware operators exfiltrate data through MOVEit Transfer vulnerabilities before extortion' },
      { id: 'b', text: 'Extortion crew exploiting MOVEit Transfer vulnerabilities to exfiltrate data' },
      { id: 'c', text: 'Espionage implant targeting diplomatic networks in Central Asia' },
    ]);
    const a = vectors.get('a')!;
    const b = vectors.get('b')!;
    const c = vectors.get('c')!;
    expect(sparseCosine(a, b)).toBeGreaterThan(sparseCosine(a, c));
    expect(topSharedTerms(a, b)).toContain('moveit');
  });
});
