import { describe, expect, it } from 'vitest';
import { createMockUserContext, testRenderHook } from '../../../../../utils/tests/test-render';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';

const ENRICHER = ['INVESTIGATION_INUPDATE', 'KNOWLEDGE_KNENRICHMENT'];

/**
 * Renders the hook for a user with the given capabilities and access right on the investigation.
 */
const renderRights = (capabilities: string[], accessRight: string) => {
  const { hook } = testRenderHook(
    () => useInvestigationEnrichmentRights(accessRight),
    {
      userContext: createMockUserContext({
        me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })) },
      }),
    },
  );
  return hook.result.current;
};

describe('Hook: useInvestigationEnrichmentRights', () => {
  it('lets an editor with every right launch and refresh', () => {
    expect(renderRights([...ENRICHER, 'KNOWLEDGE_KNUPDATE_KNDELETE'], 'edit')).toEqual({ canLaunch: true, canRefresh: true });
  });

  it('lets an editor without knowledge update refresh but not launch', () => {
    expect(renderRights(ENRICHER, 'edit')).toEqual({ canLaunch: false, canRefresh: true });
  });

  it('refuses both actions without the enrichment capability', () => {
    expect(renderRights(['INVESTIGATION_INUPDATE', 'KNOWLEDGE_KNUPDATE'], 'edit')).toEqual({ canLaunch: false, canRefresh: false });
  });

  it('refuses both actions to a view only member', () => {
    expect(renderRights([...ENRICHER, 'KNOWLEDGE_KNUPDATE'], 'view')).toEqual({ canLaunch: false, canRefresh: false });
  });
});
