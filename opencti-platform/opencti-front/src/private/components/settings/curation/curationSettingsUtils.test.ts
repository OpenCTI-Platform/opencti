import { describe, expect, it } from 'vitest';
import { adjudicationAgentOptions, authorityAttributeOptions, missingAdjudicationPrerequisite } from './curationSettingsUtils';

describe('curation settings', () => {
  const curator = { agent_slug: 'opencti-curator', agent_name: 'OpenCTI Curator' };

  it('keeps a stored agent XTM One no longer lists, so a save never drops it', () => {
    expect(adjudicationAgentOptions([curator], 'opencti-curator')).toEqual([curator]);
    expect(adjudicationAgentOptions([curator], 'retired-agent')).toEqual([curator, { agent_slug: 'retired-agent', agent_name: 'retired-agent' }]);
    expect(adjudicationAgentOptions([], null)).toEqual([]);
  });

  it('offers the attributes of the entity type by their translated label, the stored one kept', () => {
    const translate = (label: string) => ({ Description: 'Description', Aliases: 'Alias', Name: 'Nom' }[label] ?? label);
    const attributes = [{ name: 'name', label: 'Name' }, { name: 'description', label: 'Description' }, { name: 'aliases', label: 'Aliases' }];
    expect(authorityAttributeOptions(attributes, 'description', translate)).toEqual([
      { name: 'aliases', label: 'Alias' },
      { name: 'description', label: 'Description' },
      { name: 'name', label: 'Nom' },
    ]);
    expect(authorityAttributeOptions(undefined, 'x_custom', translate)).toEqual([{ name: 'x_custom', label: 'x_custom' }]);
    expect(authorityAttributeOptions(undefined, '', translate)).toEqual([]);
  });

  it('names the prerequisite adjudication is missing, the Enterprise Edition first', () => {
    expect(missingAdjudicationPrerequisite({ enterprise_edition: false, xtm_one_configured: false })).toBe('enterprise_edition');
    expect(missingAdjudicationPrerequisite({ enterprise_edition: true, xtm_one_configured: false })).toBe('xtm_one');
    expect(missingAdjudicationPrerequisite({ enterprise_edition: true, xtm_one_configured: true })).toBeNull();
  });
});
