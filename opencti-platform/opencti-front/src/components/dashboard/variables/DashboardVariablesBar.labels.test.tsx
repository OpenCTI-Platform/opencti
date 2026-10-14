import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariablesBar from './DashboardVariablesBar';
import DashboardVariableChip from './DashboardVariableChip';

// Not mocked here: the bar goes through the real labels hooks and the (mock) Relay environment.
const idVariable = (n: number, type: 'label' | 'marking' | 'user'): DashboardVariable => ({
  id: `var-${n}`,
  name: `Variable ${n}`,
  type,
  restriction: { mode: 'none' },
  defaultValue: null,
});
const text: DashboardVariable = { id: 'var-4', name: 'Sector', type: 'text', restriction: { mode: 'none' }, defaultValue: null };

const renderBar = (variables: DashboardVariable[], values: [string, string][]) => testRender(
  <DashboardVariablesBar
    variables={variables}
    values={new Map(values)}
    defaults={new Map(values)}
    usedInWidgetIdsByVariable={new Map(variables.map(({ id }) => [id, ['w-1']]))}
    canManage
    onSetValue={() => {}}
    onReset={() => {}}
    onSetAsDefaults={() => Promise.resolve()}
  />,
);

describe('DashboardVariablesBar labels', () => {
  it('resolves the values of all the id-backed chips with one single query', () => {
    const variables = [idVariable(1, 'label'), idVariable(2, 'marking'), idVariable(3, 'user'), text];
    const { relayEnv } = renderBar(variables, [['var-1', 'label-id'], ['var-2', 'marking-id'], ['var-3', 'user-id'], ['var-4', 'Energy']]);
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.node.operation.name).toBe('FilterValuesContentQuery');
    expect(operations[0].request.variables.filters.filters).toEqual([
      { key: ['id'], values: ['label-id', 'marking-id', 'user-id'], operator: 'eq', mode: 'or' },
    ]);
  });

  it('asks for a shared id once and gives each chip its label, Restricted for the unresolvable one only', () => {
    const variables = [idVariable(1, 'label'), idVariable(2, 'marking'), idVariable(3, 'user')];
    const { relayEnv } = renderBar(variables, [['var-1', 'shared-id'], ['var-2', 'shared-id'], ['var-3', 'gone-id']]);
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.variables.filters.filters[0].values).toEqual(['shared-id', 'gone-id']);
    // Still resolving: no chip shows an id.
    expect(screen.getByRole('button', { name: 'Variable 1 : …' })).toBeInTheDocument();
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { filtersRepresentatives: [{ representativeId: 'shared-id', value: 'TLP:RED', entity_type: 'Marking-Definition', color: null }] },
      });
    });
    expect(screen.getByRole('button', { name: 'Variable 1 : TLP:RED' }).className).not.toMatch(/feedback-error/);
    expect(screen.getByRole('button', { name: 'Variable 2 : TLP:RED' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Variable 3 : Restricted' }).className).toMatch(/feedback-error/);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('sends no query when no chip holds an id', () => {
    const { relayEnv } = renderBar([text, idVariable(1, 'label')], [['var-4', 'Energy']]);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.getByRole('button', { name: 'Sector : Energy' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Variable 1 : Not set' })).toBeInTheDocument();
  });
});

describe('DashboardVariableChip labels', () => {
  const marking = idVariable(2, 'marking');

  it('resolves its own value when used alone', () => {
    const { relayEnv } = testRender(<DashboardVariableChip variable={marking} value="marking-id" usedInWidgetIds={['w-1']} onChange={() => {}} />);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
  });

  it('resolves nothing by itself when its labels are provided', () => {
    const valueLabels = { labels: new Map([['marking-id', 'TLP:RED']]), restricted: new Set<string>() };
    const { relayEnv } = testRender(
      <DashboardVariableChip variable={marking} value="marking-id" valueLabels={valueLabels} usedInWidgetIds={['w-1']} onChange={() => {}} />,
    );
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.getByRole('button', { name: 'Variable 2 : TLP:RED' })).toBeInTheDocument();
  });
});
