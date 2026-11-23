import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ProcedureComponentsComponent from './ProcedureComponents';
import type { ProcedureComponents_procedure$data } from './__generated__/ProcedureComponents_procedure.graphql';

// useFragment is mocked as an identity function below, so at runtime the card
// receives the raw fragment `$data` object instead of a `$key` fragment ref.
const ProcedureComponents = ProcedureComponentsComponent as unknown as (
  props: { procedure: ProcedureComponents_procedure$data },
) => React.JSX.Element;

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});

const component = (index: number, type: string, entityType: string, value: string) => ({
  relationship_id: `relationship-${index}`,
  component_index: index,
  component_type: type,
  observable: { id: `observable-${index}`, entity_type: entityType, observable_value: value },
});

const build = (components: ReturnType<typeof component>[]) => ({ id: 'procedure-1', procedureComponents: components }) as unknown as ProcedureComponents_procedure$data;

const rowValues = () => screen.getAllByRole('row').slice(1).map((row) => within(row).getAllByRole('cell').map((cell) => cell.textContent));

describe('ProcedureComponents', () => {
  it('lists the components in index order', () => {
    testRender(
      <ProcedureComponents procedure={build([
        component(1, 'primary', 'Text', 'start backup'),
        component(0, 'primary', 'Process', 'wbadmin.exe'),
        component(2, 'secondary', 'Text', '-quiet'),
      ])}
      />,
    );
    expect(rowValues()).toEqual([
      ['0', 'Primary', 'Process', 'wbadmin.exe'],
      ['1', 'Primary', 'Text', 'start backup'],
      ['2', 'Secondary', 'Text', '-quiet'],
    ]);
    expect(screen.queryByText('Sequence incomplete')).toBeNull();
  });

  it('warns when the sequence has a gap', () => {
    testRender(
      <ProcedureComponents procedure={build([
        component(0, 'primary', 'Process', 'wbadmin.exe'),
        component(1, 'primary', 'Text', 'start backup'),
        component(3, 'secondary', 'Text', '-quiet'),
      ])}
      />,
    );
    expect(screen.getByText('Sequence incomplete')).toBeDefined();
  });

  it('says when there are no components', () => {
    testRender(<ProcedureComponents procedure={build([])} />);
    expect(screen.getByText('No components')).toBeDefined();
    expect(screen.queryByRole('table')).toBeNull();
  });
});
