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

const REVIEW_REASON = 'You need the Ask for knowledge enrichment and Create / Update investigations capabilities to review enrichment results.';

describe('Hook: useInvestigationEnrichmentRights', () => {
  it('lets an editor with every right launch, refresh and review', () => {
    expect(renderRights([...ENRICHER, 'KNOWLEDGE_KNUPDATE_KNDELETE'], 'edit')).toEqual({ canEdit: true, canLaunch: true, canRefresh: true, reviewDisabledReason: undefined });
  });

  it('lets an editor without knowledge update refresh and review but not launch', () => {
    expect(renderRights(ENRICHER, 'edit')).toEqual({ canEdit: true, canLaunch: false, canRefresh: true, reviewDisabledReason: undefined });
  });

  it('refuses both actions without the enrichment capability, and says why the results cannot be reviewed', () => {
    expect(renderRights(['INVESTIGATION_INUPDATE', 'KNOWLEDGE_KNUPDATE'], 'edit')).toEqual({ canEdit: true, canLaunch: false, canRefresh: false, reviewDisabledReason: REVIEW_REASON });
  });

  it('says why the results cannot be reviewed to an editor without the investigation update capability', () => {
    expect(renderRights(['KNOWLEDGE_KNENRICHMENT'], 'admin').reviewDisabledReason).toBe(REVIEW_REASON);
  });

  it('refuses both actions to a view only member, whose review dialog tells about the view access instead', () => {
    expect(renderRights([...ENRICHER, 'KNOWLEDGE_KNUPDATE'], 'view')).toEqual({ canEdit: false, canLaunch: false, canRefresh: false, reviewDisabledReason: undefined });
  });
});
