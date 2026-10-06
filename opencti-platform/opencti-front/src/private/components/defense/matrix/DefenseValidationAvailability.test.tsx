import React, { Suspense } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import type { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import DefenseGapsLines, { defenseGapsLinesQuery } from './DefenseGapsLines';
import DefenseTechniqueDrawer from './DefenseTechniqueDrawer';
import { DefenseGapsLinesPaginationQuery } from './__generated__/DefenseGapsLinesPaginationQuery.graphql';
import { DEFAULT_DEFENSE_SCOPE, DEFENSE_LEVEL_DETECTION_AVAILABLE, DEFENSE_LEVEL_DETECTION_DEPLOYED } from './defenseMatrix-utils';

const knowledgeEditor = createMockUserContext({
  me: { name: 'editor', user_email: 'editor@opencti.io', capabilities: [{ name: KNOWLEDGE_KNUPDATE }] },
});

// Every variable of the query is given: the mock environment matches a request on its exact variables
const GAPS_VARIABLES = { platformIds: null, threatScope: null, filter: null, count: 50, cursor: null, orderBy: null, orderMode: null };

const GapsLines = () => {
  const queryRef = useQueryLoading<DefenseGapsLinesPaginationQuery>(defenseGapsLinesQuery, GAPS_VARIABLES);
  return queryRef ? (
    <Suspense fallback={<span>loading</span>}>
      <DefenseGapsLines queryRef={queryRef} scope={DEFAULT_DEFENSE_SCOPE} />
    </Suspense>
  ) : null;
};

const waitForQuery = (relayEnv: RelayMockEnvironment) => waitFor(() => expect(relayEnv.mock.getAllOperations().length).toBeGreaterThan(0));

const renderGapsLines = async (validationAvailable: boolean) => {
  const { relayEnv } = testRender(<GapsLines />, { userContext: knowledgeEditor });
  await waitForQuery(relayEnv);
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      DefenseCoverageStatus: () => ({ validation_available: validationAvailable }),
      DefenseGap: () => ({
        attack_pattern_id: 'attack-pattern-1',
        platform_id: 'platform-1',
        level: 0,
        detection: 'none',
        validated: 'none',
        recommended_action: 'add_telemetry',
        threats_count: 0,
        last_validation_requested_at: null,
      }),
    }));
  });
  await screen.findByTestId('defense-gaps-table');
};

const renderDrawer = async (validationAvailable: boolean, level: number) => {
  const { relayEnv } = testRender(
    <DefenseTechniqueDrawer attackPatternId="attack-pattern-1" title="T1059" scope={DEFAULT_DEFENSE_SCOPE} onClose={vi.fn()} allowValidation />,
    { userContext: knowledgeEditor },
  );
  await waitForQuery(relayEnv);
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      DefenseCoverageStatus: () => ({ validation_available: validationAvailable }),
      DefenseTechnique: () => ({ computed_at: null, dataComponents: [], rules: [], validations: [], mitigations: [], threats: [], gaps: [] }),
      DefenseMatrixCell: () => ({
        level,
        detection: level === DEFENSE_LEVEL_DETECTION_DEPLOYED ? 'deployed' : 'available',
        validated: 'none',
        recommended_action: level === DEFENSE_LEVEL_DETECTION_DEPLOYED ? 'validate' : 'deploy_rule',
        mitigated: false,
        last_result_at: null,
        platforms: [],
      }),
    }));
  });
  await screen.findByTestId('defense-technique-drawer-content');
};

describe('Defense validation actions', () => {
  it('should offer the gap selection and the validation while an OpenAEV connector is active', async () => {
    await renderGapsLines(true);
    expect(screen.getByTestId('defense-gaps-validate')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Select all' })).toBeInTheDocument();
  });

  it('should hide the gap selection and the validation without an OpenAEV connector', async () => {
    await renderGapsLines(false);
    expect(screen.queryByTestId('defense-gaps-validate')).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });

  it.each([DEFENSE_LEVEL_DETECTION_DEPLOYED, DEFENSE_LEVEL_DETECTION_AVAILABLE])('should offer the validation of a level %i technique while an OpenAEV connector is active', async (level) => {
    await renderDrawer(true, level);
    expect(screen.getByTestId('defense-technique-validate')).toBeInTheDocument();
    expect(screen.queryByTestId('defense-technique-openaev-not-connected')).not.toBeInTheDocument();
  });

  it.each([DEFENSE_LEVEL_DETECTION_DEPLOYED, DEFENSE_LEVEL_DETECTION_AVAILABLE])('should not offer the validation of a level %i technique without an OpenAEV connector', async (level) => {
    await renderDrawer(false, level);
    expect(screen.queryByTestId('defense-technique-validate')).not.toBeInTheDocument();
    // The drawer says why and links to the setup instead
    expect(screen.getByTestId('defense-technique-openaev-not-connected')).toBeInTheDocument();
  });
});
