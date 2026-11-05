import React, { Suspense, useEffect, useMemo } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { useQueryLoader } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { OperationDescriptor } from 'relay-runtime';
import testRender from '../../../../../utils/tests/test-render';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import AttackPatternsMatrix, { attackPatternsMatrixQuery } from './AttackPatternsMatrix';
import AttackPatternsMatrixColumns from './AttackPatternsMatrixColumns';
import { getMatrixConfig, MatrixVariant } from './attackPatternsMatrixConfig';
import { AttackPatternsMatrixQuery } from './__generated__/AttackPatternsMatrixQuery.graphql';

vi.mock('../../../../../utils/hooks/useTopBanner', () => ({ default: () => ({ height: 0 }) }));
vi.mock('../../../../../utils/hooks/useQueryLoading', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../../utils/hooks/useQueryLoading')>();
  return { ...actual, default: vi.fn(actual.default) };
});

const ZETA_ID = 'attack-pattern--zeta';
const ALPHA_ID = 'attack-pattern--alpha';
const SUB_ID = 'attack-pattern--alpha-sub';

const technique = (id: string, name: string, x_mitre_id: string, subAttackPatterns: unknown[] = []) => ({
  attack_pattern_id: id,
  name,
  description: null,
  x_mitre_id,
  subAttackPatterns,
  subAttackPatternsSearchText: null,
  killChainPhasesIds: [],
});

const DEFAULT_SUBS = [{ attack_pattern_id: SUB_ID, name: 'Sub', description: null, x_mitre_id: 'T1548.001' }];
// API order deliberately differs from both MITRE ID order and name order.
const UNORDERED_SUBS = [
  { attack_pattern_id: 'attack-pattern--sub-004', name: 'Sub Z', description: null, x_mitre_id: 'T1548.004' },
  { attack_pattern_id: 'attack-pattern--sub-001', name: 'Sub A', description: null, x_mitre_id: 'T1548.001' },
];

const matrixResolver = (alphaSubs: unknown[] = DEFAULT_SUBS) => (operation: OperationDescriptor) => MockPayloadGenerator.generate(operation, {
  AttackPatternsMatrix: () => ({
    attackPatternsOfPhases: [{
      kill_chain_id: 'phase-execution',
      kill_chain_name: 'mitre-attack',
      phase_name: 'execution',
      x_opencti_order: 1,
      attackPatterns: [
        technique(ZETA_ID, 'Zeta', 'T1078'),
        technique(ALPHA_ID, 'Alpha', 'T1548', alphaSubs),
      ],
    }],
  }),
});
const resolveMatrix = matrixResolver();

const LABEL_PATTERN = /^(Alpha|Zeta|T1078 - Zeta|T1548 - Alpha)$/;
const labels = () => screen.getAllByText(LABEL_PATTERN).map((el) => el.textContent);

interface HarnessProps {
  variant?: MatrixVariant;
  isModeOnlyActive?: boolean;
}

// Loads the query the way AttackPatternsMatrix does, then renders the columns directly.
const ColumnsHarness = ({ variant, isModeOnlyActive = false }: HarnessProps) => {
  const queryRef = useQueryLoading<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, {});
  const config = useMemo(() => getMatrixConfig(variant, false), [variant]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={<span>loading</span>}>
      <AttackPatternsMatrixColumns
        queryRef={queryRef}
        config={config}
        attackPatterns={[{ id: ZETA_ID }]}
        entityType="Report"
        searchTerm=""
        handleAdd={vi.fn()}
        selectedKillChain="mitre-attack"
        isModeOnlyActive={isModeOnlyActive}
      />
    </Suspense>
  );
};

const renderColumns = async ({ alphaSubs, ...props }: HarnessProps & { alphaSubs?: unknown[] } = {}) => {
  const rendered = testRender(<ColumnsHarness {...props} />);
  await act(async () => rendered.relayEnv.mock.resolveMostRecentOperation(matrixResolver(alphaSubs)));
  await screen.findAllByText(LABEL_PATTERN);
  return rendered;
};

describe('AttackPatternsMatrixColumns', () => {
  describe('default variant', () => {
    it('sorts techniques by name and shows plain names', async () => {
      await renderColumns();
      expect(labels()).toEqual(['Alpha', 'Zeta']);
    });

    it('keeps the current red badge background', async () => {
      const { container } = await renderColumns();
      const badge = container.querySelector('.MuiBadge-badge');
      expect(badge).not.toBeNull();
      // COLORS.BADGE in AttackPatternsMatrixColumns.tsx
      expect(getComputedStyle(badge as Element).backgroundColor).toBe('rgb(250, 94, 94)');
    });

    it('opens a menu with View and Add', async () => {
      const { user } = await renderColumns();
      await user.click(screen.getByText('Zeta'));
      expect(await screen.findByRole('menuitem', { name: 'View' })).toBeInTheDocument();
      expect(screen.getByRole('menuitem', { name: 'Add' })).toBeInTheDocument();
    });

    it('keeps sub-techniques in API order', async () => {
      const { user } = await renderColumns({ alphaSubs: UNORDERED_SUBS });
      await user.click(screen.getByRole('button', { name: 'Expand' }));
      await screen.findByText('Sub Z');
      expect(screen.getAllByText(/^Sub [AZ]$/).map((el) => el.textContent)).toEqual(['Sub Z', 'Sub A']);
    });

    it('renders leaf cells as non-button elements', async () => {
      await renderColumns();
      expect(screen.queryByRole('button', { name: 'Zeta' })).not.toBeInTheDocument();
    });
  });

  describe('investigation variant', () => {
    it('prefixes labels with the MITRE ID and sorts by it', async () => {
      await renderColumns({ variant: 'investigation' });
      expect(labels()).toEqual(['T1078 - Zeta', 'T1548 - Alpha']);
    });

    it('prefixes sub-technique labels with their MITRE ID', async () => {
      const { user } = await renderColumns({ variant: 'investigation' });
      await user.click(screen.getByRole('button', { name: 'Expand' }));
      expect(await screen.findByText('T1548.001 - Sub')).toBeInTheDocument();
    });

    it('sorts sub-techniques by MITRE ID', async () => {
      const { user } = await renderColumns({ variant: 'investigation', alphaSubs: UNORDERED_SUBS });
      await user.click(screen.getByRole('button', { name: 'Expand' }));
      await screen.findByText('T1548.001 - Sub A');
      expect(screen.getAllByText(/^T1548\.\d+ - Sub [AZ]$/).map((el) => el.textContent))
        .toEqual(['T1548.001 - Sub A', 'T1548.004 - Sub Z']);
    });

    it('uses the neutral badge colours', async () => {
      const { container } = await renderColumns({ variant: 'investigation' });
      const style = getComputedStyle(container.querySelector('.MuiBadge-badge') as Element);
      expect(style.backgroundColor).toBe('var(--black-800)');
      expect(style.color).toBe('var(--gray-100)');
    });

    it('opens a menu with View only, in a new tab', async () => {
      const { user } = await renderColumns({ variant: 'investigation' });
      await user.click(screen.getByText('T1078 - Zeta'));
      const view = await screen.findByRole('menuitem', { name: 'View' });
      expect(view).toHaveAttribute('target', '_blank');
      expect(screen.queryByRole('menuitem', { name: 'Add' })).not.toBeInTheDocument();
    });

    it('renders leaf cells as buttons', async () => {
      await renderColumns({ variant: 'investigation' });
      const cell = screen.getByRole('button', { name: 'T1078 - Zeta' });
      expect(cell.tagName).toBe('BUTTON');
      expect(cell).toHaveAttribute('type', 'button');
    });
  });

  describe('isModeOnlyActive', () => {
    it.each<[MatrixVariant | undefined, string]>([
      [undefined, 'Zeta'],
      ['investigation', 'T1078 - Zeta'],
    ])('shows only the used techniques (variant %s)', async (variant, expected) => {
      await renderColumns({ variant, isModeOnlyActive: true });
      expect(labels()).toEqual([expected]);
    });
  });
});

describe('AttackPatternsMatrix', () => {
  it('loads its own query and applies the variant when no queryRef is given', async () => {
    const { relayEnv, container } = testRender(
      <AttackPatternsMatrix
        attackPatterns={[{ id: ZETA_ID }]}
        entityType="Report"
        selectedKillChain="mitre-attack"
        isModeOnlyActive={false}
        variant="investigation"
        exportElementId="matrix-export"
      />,
    );
    await act(async () => relayEnv.mock.resolveMostRecentOperation(resolveMatrix));
    await screen.findAllByText(LABEL_PATTERN);
    expect(labels()).toEqual(['T1078 - Zeta', 'T1548 - Alpha']);
    expect(container.querySelector('#matrix-export')).not.toBeNull();
  });

  it('reuses a given queryRef without loading the query again', async () => {
    // The caller loads the query itself, without useQueryLoading, so any call to it comes from the matrix.
    const Preloaded = () => {
      const [queryRef, loadQuery] = useQueryLoader<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery);
      useEffect(() => {
        loadQuery({});
      }, []);
      if (!queryRef) return null;
      return (
        <AttackPatternsMatrix
          queryRef={queryRef}
          attackPatterns={[{ id: ZETA_ID }]}
          entityType="Report"
          selectedKillChain="mitre-attack"
          isModeOnlyActive={false}
        />
      );
    };
    vi.mocked(useQueryLoading).mockClear();
    const { relayEnv } = testRender(<Preloaded />);
    await act(async () => relayEnv.mock.resolveMostRecentOperation(resolveMatrix));
    await screen.findAllByText(LABEL_PATTERN);
    expect(labels()).toEqual(['Alpha', 'Zeta']);
    expect(useQueryLoading).not.toHaveBeenCalled();
  });
});
