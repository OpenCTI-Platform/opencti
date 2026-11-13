import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const CREATE_QUERY = gql`
  mutation ProcedureAdd($input: ProcedureAddInput!) {
    procedureAdd(input: $input) {
      id
      standard_id
      name
    }
  }
`;

const READ_QUERY = gql`
  query procedure($id: String!) {
    procedure(id: $id) {
      id
      standard_id
      name
      x_mitre_platforms
      killChainPhases {
        id
        phase_name
      }
      procedureObservables {
        edges {
          node {
            id
          }
        }
      }
      procedureCommand {
        id
      }
      procedureSources {
        id
      }
      toStix
    }
  }
`;

const LIST_QUERY = gql`
  query procedures($first: Int, $filters: FilterGroup) {
    procedures(first: $first, filters: $filters) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation procedureDelete($id: ID!) {
    procedureDelete(id: $id)
  }
`;

const OBSERVABLE_ADD = gql`
  mutation StixCyberObservableAdd($type: String!, $IPv4Addr: IPv4AddrAddInput, $Process: ProcessAddInput) {
    stixCyberObservableAdd(type: $type, IPv4Addr: $IPv4Addr, Process: $Process) {
      id
      standard_id
    }
  }
`;

const OBSERVABLE_DELETE = gql`
  mutation stixCyberObservableDelete($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

const ORGANIZATION_ADD = gql`
  mutation OrganizationAdd($input: OrganizationAddInput!) {
    organizationAdd(input: $input) {
      id
      standard_id
    }
  }
`;

const ORGANIZATION_DELETE = gql`
  mutation organizationDelete($id: ID!) {
    organizationDelete(id: $id)
  }
`;

const KILL_CHAIN_PHASE_ADD = gql`
  mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) {
      id
    }
  }
`;

const KILL_CHAIN_PHASE_DELETE = gql`
  mutation killChainPhaseDelete($id: ID!) {
    killChainPhaseEdit(id: $id) {
      delete
    }
  }
`;

const createdProcedureIds: string[] = [];

const addProcedureAsAdmin = async (input: Record<string, unknown>) => {
  const result = await queryAsAdminWithSuccess({ query: CREATE_QUERY, variables: { input } });
  const procedure = result.data?.procedureAdd;
  if (!createdProcedureIds.includes(procedure.id)) {
    createdProcedureIds.push(procedure.id);
  }
  return procedure;
};

const readProcedure = async (id: string) => {
  const result = await queryAsAdmin({ query: READ_QUERY, variables: { id } });
  return result.data?.procedure;
};

describe('Procedure resolver', () => {
  let observableId: string;
  let processId: string;
  let organizationId: string;
  let killChainPhaseId: string;
  let fullProcedureId: string;

  beforeAll(async () => {
    const observable = await queryAsAdminWithSuccess({
      query: OBSERVABLE_ADD,
      variables: { type: 'IPv4-Addr', IPv4Addr: { value: '198.51.100.27' } },
    });
    observableId = observable.data?.stixCyberObservableAdd.id;
    const process = await queryAsAdminWithSuccess({
      query: OBSERVABLE_ADD,
      variables: { type: 'Process', Process: { command_line: 'cmd.exe /c powershell -enc SQBFAFgA' } },
    });
    processId = process.data?.stixCyberObservableAdd.id;
    const organization = await queryAsAdminWithSuccess({
      query: ORGANIZATION_ADD,
      variables: { input: { name: 'Procedure test source organization' } },
    });
    organizationId = organization.data?.organizationAdd.id;
    const killChainPhase = await queryAsAdminWithSuccess({
      query: KILL_CHAIN_PHASE_ADD,
      variables: { input: { kill_chain_name: 'mitre-attack', phase_name: 'procedure-test-phase', x_opencti_order: 99 } },
    });
    killChainPhaseId = killChainPhase.data?.killChainPhaseAdd.id;
  });

  afterAll(async () => {
    for (let i = 0; i < createdProcedureIds.length; i += 1) {
      const procedure = await readProcedure(createdProcedureIds[i]);
      if (procedure) {
        await queryAsAdmin({ query: DELETE_QUERY, variables: { id: createdProcedureIds[i] } });
      }
    }
    await queryAsAdmin({ query: OBSERVABLE_DELETE, variables: { id: observableId } });
    await queryAsAdmin({ query: OBSERVABLE_DELETE, variables: { id: processId } });
    await queryAsAdmin({ query: ORGANIZATION_DELETE, variables: { id: organizationId } });
    await queryAsAdmin({ query: KILL_CHAIN_PHASE_DELETE, variables: { id: killChainPhaseId } });
  });

  it('creates a procedure with a random UUIDv4 standard id', async () => {
    const p = await addProcedureAsAdmin({ name: 'Run PowerShell via cmd.exe' });
    expect(p.standard_id).toMatch(/^x-opencti-procedure--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('creates two entities for two identical inputs', async () => {
    const a = await addProcedureAsAdmin({ name: 'Same name' });
    const b = await addProcedureAsAdmin({ name: 'Same name' });
    expect(a.id).not.toBe(b.id);
    expect(a.standard_id).not.toBe(b.standard_id);
  });

  it('keeps a provided x-opencti-procedure stix id and upserts on it', async () => {
    const stixId = 'x-opencti-procedure--5e0040b0-42df-46d2-8e7f-0fa3d753b75d';
    const a = await addProcedureAsAdmin({ name: 'Imported', stix_id: stixId });
    const b = await addProcedureAsAdmin({ name: 'Imported', stix_id: stixId });
    expect(a.standard_id).toBe(stixId);
    expect(b.id).toBe(a.id);
  });

  it('stores observable, command and source refs and kill chain phases', async () => {
    const p = await addProcedureAsAdmin({
      name: 'Encoded PowerShell from cmd.exe',
      x_mitre_platforms: ['windows'],
      procedureObservables: [observableId],
      procedureCommand: processId,
      procedureSources: [organizationId],
      killChainPhases: [killChainPhaseId],
    });
    fullProcedureId = p.id;
    const procedure = await readProcedure(fullProcedureId);
    expect(procedure.x_mitre_platforms).toEqual(['windows']);
    expect(procedure.procedureObservables.edges.map((e: { node: { id: string } }) => e.node.id)).toEqual([observableId]);
    expect(procedure.procedureCommand.id).toBe(processId);
    expect(procedure.procedureSources.map((s: { id: string }) => s.id)).toEqual([organizationId]);
    expect(procedure.killChainPhases.map((k: { id: string }) => k.id)).toEqual([killChainPhaseId]);
  });

  it('lists procedures filtered by procedureObservables', async () => {
    const filters = {
      mode: 'and',
      filters: [{ key: ['procedureObservables'], values: [observableId] }],
      filterGroups: [],
    };
    const result = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10, filters } });
    const ids = result.data?.procedures.edges.map((e: { node: { id: string } }) => e.node.id);
    expect(ids).toEqual([fullProcedureId]);
  });

  it('converts to STIX with the PDF property names', async () => {
    const procedure = await readProcedure(fullProcedureId);
    const stix = JSON.parse(procedure.toStix);
    expect(stix.type).toBe('x-opencti-procedure');
    expect(stix).toHaveProperty('x_observable_refs');
    expect(stix).toHaveProperty('x_command_ref');
    expect(stix).toHaveProperty('x_source_refs');
    expect(stix.platforms).toEqual(['windows']);
    expect(stix.kill_chain_phases).toEqual([{ kill_chain_name: 'mitre-attack', phase_name: 'procedure-test-phase' }]);
    expect(stix).not.toHaveProperty('x_mitre_platforms');
    expect(stix).not.toHaveProperty('x_log_source_refs');
  });

  it('deletes a procedure', async () => {
    const p = await addProcedureAsAdmin({ name: 'To delete' });
    const result = await queryAsAdmin({ query: DELETE_QUERY, variables: { id: p.id } });
    expect(result.data?.procedureDelete).toBe(p.id);
    expect(await readProcedure(p.id)).toBeNull();
  });
});
