import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { getNodeText, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ProcedureDetailsComponent from './ProcedureDetails';
import type { ProcedureDetails_procedure$data } from './__generated__/ProcedureDetails_procedure.graphql';

// useFragment is mocked as an identity function below, so at runtime ProcedureDetails
// receives the raw fragment `$data` object instead of a `$key` fragment ref.
const ProcedureDetails = ProcedureDetailsComponent as unknown as (
  props: { procedure: ProcedureDetails_procedure$data },
) => React.JSX.Element;

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});

const buildProcedure = (overrides: Record<string, unknown> = {}) => ({
  id: 'procedure-1',
  entity_type: 'Procedure',
  customFieldValues: [],
  description: 'Enumerates local accounts',
  x_procedure_type: 'discovery-procedure',
  x_mitre_platforms: ['windows', 'linux'],
  first_observed: '2024-01-02T10:00:00.000Z',
  last_observed: '2024-02-03T10:00:00.000Z',
  x_execution_start: '2024-03-04T10:00:00.000Z',
  x_execution_end: '2024-04-05T10:00:00.000Z',
  x_fingerprint: '0123456789abcdef0123456789abcdef',
  killChainPhases: [
    { id: 'kcp-1', entity_type: 'Kill-Chain-Phase', kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 1 },
    { id: 'kcp-2', entity_type: 'Kill-Chain-Phase', kill_chain_name: 'mitre-attack', phase_name: 'discovery', x_opencti_order: 2 },
  ],
  procedureCommand: { id: 'process-1', entity_type: 'Process', observable_value: 'cmd.exe /c whoami' },
  procedureObservables: {
    edges: [
      { node: { id: 'domain-1', entity_type: 'Domain-Name', observable_value: 'evil.example.com' } },
    ],
  },
  procedureSources: [
    { id: 'organization-1', entity_type: 'Organization', name: 'Example source' },
  ],
  ...overrides,
} as unknown as ProcedureDetails_procedure$data);

describe('Component: ProcedureDetails', () => {
  it('displays the procedure properties', () => {
    testRender(<ProcedureDetails procedure={buildProcedure()} />);

    expect(screen.getByText('Procedure type')).toBeInTheDocument();
    expect(screen.getByText('discovery-procedure')).toBeInTheDocument();
    expect(screen.getByText('Platforms')).toBeInTheDocument();
    expect(screen.getByText('Windows, Linux')).toBeInTheDocument();
    expect(screen.getByText('Kill chain phases')).toBeInTheDocument();
    expect(screen.getByText('execution')).toBeInTheDocument();
    expect(screen.getByText('discovery')).toBeInTheDocument();
    expect(screen.getByText('First observed')).toBeInTheDocument();
    expect(screen.getByText(/January 2, 2024/)).toBeInTheDocument();
    expect(screen.getByText('Last observed')).toBeInTheDocument();
    expect(screen.getByText(/February 3, 2024/)).toBeInTheDocument();
    expect(screen.getByText('Execution start')).toBeInTheDocument();
    expect(screen.getByText(/March 4, 2024/)).toBeInTheDocument();
    expect(screen.getByText('Execution end')).toBeInTheDocument();
    expect(screen.getByText(/April 5, 2024/)).toBeInTheDocument();
    expect(screen.getByText('Fingerprint')).toBeInTheDocument();
    expect(screen.getByText('0123456789abcdef0123456789abcdef')).toBeInTheDocument();
  });

  it('links the command, the observables and the sources', () => {
    testRender(<ProcedureDetails procedure={buildProcedure()} />);

    expect(screen.getByText('Command')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /cmd\.exe \/c whoami/ })).toHaveAttribute('href', '/dashboard/observations/observables/process-1');
    expect(screen.getByText('Observables')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /evil\.example\.com/ })).toHaveAttribute('href', '/dashboard/observations/observables/domain-1');
    expect(screen.getByText('Sources')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Example source/ })).toHaveAttribute('href', '/dashboard/entities/organizations/organization-1');
  });

  it('displays an empty value for each missing property', () => {
    testRender(
      <ProcedureDetails
        procedure={buildProcedure({
          x_procedure_type: null,
          x_mitre_platforms: null,
          first_observed: null,
          last_observed: null,
          x_execution_start: null,
          x_execution_end: null,
          x_fingerprint: null,
          killChainPhases: [],
          procedureCommand: null,
          procedureObservables: { edges: [] },
          procedureSources: [],
        })}
      />,
    );

    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    // Adjacent empty values share a text container, so count the dashes rather than the nodes:
    // procedure type, platforms, kill chain phases, 4 dates, fingerprint, command, observables, sources
    const emptyValues = screen.getAllByText(/^-+$/).reduce((count, node) => count + getNodeText(node).length, 0);
    expect(emptyValues).toBe(11);
  });
});
