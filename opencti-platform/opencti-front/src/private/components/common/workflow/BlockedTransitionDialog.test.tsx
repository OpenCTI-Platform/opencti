import React from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import BlockedTransitionDialog from './BlockedTransitionDialog';
import { blockingConditionKeys, parseBlockingConditions } from './blockedTransitionConditions';
import { registerEntityEditionOpener } from '../../../../components/entityEditionOpener';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

const LONG_VALUE = 'A very long description value that must wrap fully';

const filter = (key: string | string[], values: string[]) => ({ key, values, operator: 'eq', mode: 'or' });

const conditions = {
  mode: 'and',
  filters: [filter(['objectAssignee'], ['@me']), filter('description', [LONG_VALUE])],
  filterGroups: [],
};

const renderDialog = (overrides: Partial<React.ComponentProps<typeof BlockedTransitionDialog>> = {}) => {
  const onClose = vi.fn();
  const result = testRender(
    <BlockedTransitionDialog
      open
      onClose={onClose}
      event="answer"
      entityType="Report"
      toStatusName="C"
      blockingConditions={JSON.stringify(conditions)}
      {...overrides}
    />,
    {
      userContext: createMockUserContext({
        schema: { scrs: [], sdos: [], scos: [], smos: [], filterKeysSchema: new Map([['Report', new Map()]]) },
      }),
    },
  );
  return { ...result, onClose };
};

describe('blocked transition condition helpers', () => {
  it('returns null for invalid conditions', () => {
    expect(parseBlockingConditions('not json')).toBeNull();
    expect(parseBlockingConditions(null)).toBeNull();
    expect(parseBlockingConditions('')).toBeNull();
  });

  it('lists unique keys, top level first, then nested groups', () => {
    const group = {
      mode: 'and',
      filters: [filter('objectAssignee', ['x']), filter('description', ['y']), filter('objectAssignee', ['z'])],
      filterGroups: [{ mode: 'or', filters: [filter('objectLabel', ['l'])], filterGroups: [] }],
    } as FilterGroup;
    expect(blockingConditionKeys(group)).toEqual(['objectAssignee', 'description', 'objectLabel']);
  });

  it('reads keys sent by the backend as arrays', () => {
    expect(blockingConditionKeys(conditions as unknown as FilterGroup)).toEqual(['objectAssignee', 'description']);
  });

  it('returns no keys without conditions', () => {
    expect(blockingConditionKeys(null)).toEqual([]);
  });
});

describe('BlockedTransitionDialog', () => {
  it('shows title, description and the full long value', async () => {
    const { relayEnv } = renderDialog();
    expect(screen.getByText('“answer” is not available yet')).toBeInTheDocument();
    expect(screen.getByText('Meet every condition below to move this Report to C.')).toBeInTheDocument();
    // Answer the filter representatives query the way the backend does: a text
    // value is its own representative.
    await act(async () => relayEnv.mock.resolveMostRecentOperation({
      data: {
        filtersRepresentatives: [
          { representativeId: LONG_VALUE, value: LONG_VALUE, entity_type: null, color: null },
        ],
      },
    }));
    // Filter values then load the vocabulary categories; none apply here.
    await act(async () => relayEnv.mock.resolveMostRecentOperation({ data: { vocabularyCategories: [] } }));
    expect(await screen.findByText(LONG_VALUE, { exact: false })).toBeInTheDocument();
    expect(screen.getByTestId('workflow-blocked-dialog')).toHaveTextContent(LONG_VALUE);
  });

  it('Dismiss calls onClose', () => {
    const { onClose } = renderDialog();
    fireEvent.click(screen.getByTestId('workflow-blocked-dialog-dismiss'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('hides Edit when no opener is registered', () => {
    renderDialog();
    expect(screen.queryByTestId('workflow-blocked-dialog-edit')).toBeNull();
  });

  it('Edit closes and calls the registered opener', () => {
    const open = vi.fn();
    const off = registerEntityEditionOpener(open);
    const { onClose } = renderDialog();
    const edit = screen.getByTestId('workflow-blocked-dialog-edit');
    expect(edit).toHaveTextContent('Edit Report');
    fireEvent.click(edit);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledTimes(1);
    off();
  });

  it('opens with invalid blockingConditions without crashing', () => {
    renderDialog({ blockingConditions: 'not json' });
    expect(screen.getByText('“answer” is not available yet')).toBeInTheDocument();
    expect(screen.queryAllByTestId('workflow-blocked-dialog-condition')).toHaveLength(0);
  });
});
