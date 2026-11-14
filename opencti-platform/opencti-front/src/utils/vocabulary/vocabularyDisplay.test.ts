import { describe, expect, it } from 'vitest';
import { humanizeVocabularyKey, vocabularyColor, vocabularyDescriptionForDisplay, vocabularyValueLabel } from './vocabularyDisplay';

describe('humanizeVocabularyKey', () => {
  it('turns machine keys into sentence-case labels', () => {
    expect(humanizeVocabularyKey('VERY_HIGH')).toEqual('Very high');
    expect(humanizeVocabularyKey('MEDIUM')).toEqual('Medium');
    expect(humanizeVocabularyKey('NETWORK_DEVICE')).toEqual('Network device');
    expect(humanizeVocabularyKey('production')).toEqual('Production');
    expect(humanizeVocabularyKey('yes')).toEqual('Yes');
  });

  it('keeps acronyms as they are written', () => {
    expect(humanizeVocabularyKey('AI_AGENT')).toEqual('AI agent');
    expect(humanizeVocabularyKey('AI_TARGET')).toEqual('AI target');
    expect(humanizeVocabularyKey('SAAS_APPLICATION')).toEqual('SaaS application');
    expect(humanizeVocabularyKey('MCP_SERVER')).toEqual('MCP server');
    expect(humanizeVocabularyKey('EDR')).toEqual('EDR');
  });

  it('leaves a value already written as a label untouched', () => {
    expect(humanizeVocabularyKey('Windows')).toEqual('Windows');
    expect(humanizeVocabularyKey('MacOS')).toEqual('MacOS');
    expect(humanizeVocabularyKey('Custom value with spaces')).toEqual('Custom value with spaces');
  });
});

describe('vocabularyValueLabel', () => {
  it('translates the humanized label, the stored key never reaches the catalog', () => {
    const catalog: Record<string, string> = { 'Very high': 'Très élevée' };
    const translate = (message: string) => catalog[message] ?? message;
    expect(vocabularyValueLabel('VERY_HIGH', translate)).toEqual('Très élevée');
    expect(vocabularyValueLabel('AI_AGENT', translate)).toEqual('AI agent');
  });
});

describe('vocabularyDescriptionForDisplay', () => {
  it('drops the machine suffix the forms read', () => {
    expect(vocabularyDescriptionForDisplay('AI agent that acts with tools (category: AI_TARGET)')).toEqual('AI agent that acts with tools');
    expect(vocabularyDescriptionForDisplay('Reachable from the internet')).toEqual('Reachable from the internet');
    expect(vocabularyDescriptionForDisplay(null)).toBeUndefined();
  });
});

describe('vocabularyColor, the chip colour of a value', () => {
  it('accepts a hex colour and refuses anything else, so a typo falls back to the neutral tag', () => {
    expect(vocabularyColor('#e53935')).toEqual('#e53935');
    expect(vocabularyColor(' #FB8C00 ')).toEqual('#FB8C00');
    expect(vocabularyColor('#abc')).toEqual('#abc');
    expect(vocabularyColor('red')).toBeUndefined();
    expect(vocabularyColor('url(javascript:alert(1))')).toBeUndefined();
    expect(vocabularyColor('')).toBeUndefined();
    expect(vocabularyColor(undefined)).toBeUndefined();
  });
});
