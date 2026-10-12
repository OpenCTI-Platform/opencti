import React, { Suspense } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DefenseMatrixStatus, defenseMatrixPlatformsQuery } from './DefenseMatrix';
import { DefenseMatrixPlatformsQuery } from './__generated__/DefenseMatrixPlatformsQuery.graphql';
import { ALL_DEFENSE_LAYERS, DEFAULT_DEFENSE_SCOPE } from './defenseMatrix-utils';

const UNAVAILABLE = 'The defense coverage manager is disabled on this platform: the defense coverage is not computed.';

const customizer = createMockUserContext({
  me: { name: 'customizer', user_email: 'customizer@opencti.io', capabilities: [{ name: SETTINGS_SETCUSTOMIZATION }] },
});

const Status = () => {
  const queryRef = useQueryLoading<DefenseMatrixPlatformsQuery>(defenseMatrixPlatformsQuery, {});
  return queryRef ? (
    <Suspense fallback={<span>loading</span>}>
      <DefenseMatrixStatus queryRef={queryRef} scope={DEFAULT_DEFENSE_SCOPE} onScopeChange={vi.fn()} layers={ALL_DEFENSE_LAYERS} onLayersChange={vi.fn()} />
    </Suspense>
  ) : null;
};

const renderStatus = async (computationAvailable: boolean) => {
  const { relayEnv } = testRender(<Status />, { userContext: customizer });
  await waitFor(() => expect(relayEnv.mock.getAllOperations().length).toBeGreaterThan(0));
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      Query: () => ({ defensePlatforms: [] }),
      DefenseCoverageStatus: () => ({
        computed_at: null,
        computation_available: computationAvailable,
        full_computation_requested: false,
        validation_available: false,
      }),
    }));
  });
  return screen.findByTestId('defense-matrix-recompute');
};

describe('Defense matrix recomputation', () => {
  it('should offer Recompute while a node runs the defense coverage manager', async () => {
    const recompute = await renderStatus(true);
    expect(recompute).toBeEnabled();
    expect(screen.queryByRole('button', { description: UNAVAILABLE })).not.toBeInTheDocument();
  });

  it('should disable Recompute with its reason when no node runs the defense coverage manager', async () => {
    const recompute = await renderStatus(false);
    expect(recompute).toBeDisabled();
    // The reason is on a focusable wrapper: a disabled button receives no pointer event
    const wrapper = screen.getByRole('button', { name: 'Recompute', description: UNAVAILABLE });
    expect(wrapper).toHaveAttribute('tabindex', '0');
    expect(wrapper).toHaveAttribute('aria-disabled', 'true');
    expect(wrapper).toContainElement(recompute);
    expect(screen.queryByTestId('defense-matrix-recompute-pending')).not.toBeInTheDocument();
  });
});
