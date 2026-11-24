import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUser } from '../../utils/testQueryHelper';
import { USER_EDITOR } from '../../utils/testQuery';
import { MARKING_TLP_AMBER_STRICT } from '../../../src/schema/identifier';
import { computeProcedureFingerprint } from '../../../src/modules/procedure/procedure-fingerprint';

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
      x_fingerprint
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

const ATTACK_PATTERN_ADD = gql`
  mutation AttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) {
      id
      standard_id
    }
  }
`;

const ATTACK_PATTERN_DELETE = gql`
  mutation attackPatternDelete($id: ID!) {
    attackPatternEdit(id: $id) {
      delete
    }
  }
`;

const PROCEDURE_FIELD_PATCH = gql`
  mutation procedureFieldPatch($id: ID!, $input: [EditInput]!) {
    procedureFieldPatch(id: $id, input: $input) {
      id
      x_fingerprint
    }
  }
`;

const RELATIONSHIPS_QUERY = gql`
  query procedureRelationships($filters: FilterGroup) {
    stixCoreRelationships(filters: $filters, first: 10) {
      edges {
        node {
          id
          relationship_type
          from { ... on BasicObject { id } }
          to { ... on BasicObject { id } }
        }
      }
    }
  }
`;

const RELATIONSHIP_ADD = gql`
  mutation procedureRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
    }
  }
`;

const RELATIONSHIP_DELETE = gql`
  mutation procedureRelationshipDelete($fromId: StixRef!, $toId: StixRef!, $relationship_type: String!) {
    stixCoreRelationshipDelete(fromId: $fromId, toId: $toId, relationship_type: $relationship_type)
  }
`;

const hasObservableTargets = async (procedureId: string) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: ['fromId'], values: [procedureId] },
      { key: ['relationship_type'], values: ['has-observable'] },
    ],
    filterGroups: [],
  };
  const result = await queryAsAdmin({ query: RELATIONSHIPS_QUERY, variables: { filters } });
  return result.data?.stixCoreRelationships.edges.map((e: { node: { to: { id: string } } }) => e.node.to.id);
};

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

const TEXT_ADD = gql`
  mutation procedureTextAdd($Text: TextAddInput) {
    stixCyberObservableAdd(type: "Text", Text: $Text) {
      id
    }
  }
`;

const COMPONENT_READ = gql`
  query procedureComponentRelationship($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      component_index
      component_type
      toStix
    }
  }
`;

const RELATIONSHIP_FIELD_PATCH = gql`
  mutation procedureComponentPatch($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const componentOfRelationshipIds = async (procedureId: string) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: ['toId'], values: [procedureId] },
      { key: ['relationship_type'], values: ['component-of'] },
    ],
    filterGroups: [],
  };
  const result = await queryAsAdmin({ query: RELATIONSHIPS_QUERY, variables: { filters } });
  return result.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node.id);
};

const MARKED_TEXT_ADD = gql`
  mutation procedureMarkedTextAdd($Text: TextAddInput, $objectMarking: [String]) {
    stixCyberObservableAdd(type: "Text", Text: $Text, objectMarking: $objectMarking) {
      id
    }
  }
`;

const COMPONENTS_SET = gql`
  mutation procedureComponentsSet($id: ID!, $components: [ProcedureComponentInput!]!) {
    procedureComponentsSet(id: $id, components: $components) {
      id
    }
  }
`;

const COMPONENTS_READ = gql`
  query procedureComponents($id: String!) {
    procedure(id: $id) {
      procedureComponents {
        relationship_id
        component_index
        component_type
        observable {
          id
        }
      }
    }
  }
`;

const MALWARE_ADD = gql`
  mutation procedureComponentMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) {
      id
    }
  }
`;

const MALWARE_DELETE = gql`
  mutation procedureComponentMalwareDelete($id: ID!) {
    malwareEdit(id: $id) {
      delete
    }
  }
`;

type ComponentRow = { relationship_id: string; component_index: number; component_type: string; observable: { id: string } };

const readComponents = async (procedureId: string): Promise<ComponentRow[]> => {
  const result = await queryAsAdmin({ query: COMPONENTS_READ, variables: { id: procedureId } });
  return result.data?.procedure.procedureComponents;
};

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
  let processStandardId: string;
  let organizationStandardId: string;
  let attackPatternId: string;
  let attackPatternStandardId: string;

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
    processStandardId = process.data?.stixCyberObservableAdd.standard_id;
    const organization = await queryAsAdminWithSuccess({
      query: ORGANIZATION_ADD,
      variables: { input: { name: 'Procedure test source organization' } },
    });
    organizationId = organization.data?.organizationAdd.id;
    organizationStandardId = organization.data?.organizationAdd.standard_id;
    const killChainPhase = await queryAsAdminWithSuccess({
      query: KILL_CHAIN_PHASE_ADD,
      variables: { input: { kill_chain_name: 'mitre-attack', phase_name: 'procedure-test-phase', x_opencti_order: 99 } },
    });
    killChainPhaseId = killChainPhase.data?.killChainPhaseAdd.id;
    const attackPattern = await queryAsAdminWithSuccess({
      query: ATTACK_PATTERN_ADD,
      variables: { input: { name: 'Procedure test technique', x_mitre_id: 'T9999' } },
    });
    attackPatternId = attackPattern.data?.attackPatternAdd.id;
    attackPatternStandardId = attackPattern.data?.attackPatternAdd.standard_id;
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
    await queryAsAdmin({ query: ATTACK_PATTERN_DELETE, variables: { id: attackPatternId } });
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

  it('stores observables as has-observable relationships, the command and source refs and kill chain phases', async () => {
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
    expect(await hasObservableTargets(fullProcedureId)).toEqual([observableId]);
    expect(procedure.procedureCommand.id).toBe(processId);
    expect(procedure.procedureSources.map((s: { id: string }) => s.id)).toEqual([organizationId]);
    expect(procedure.killChainPhases.map((k: { id: string }) => k.id)).toEqual([killChainPhaseId]);
  });

  it('lists the procedures that have an observable', async () => {
    const filters = {
      mode: 'and',
      filters: [{
        key: ['regardingOf'],
        values: [{ key: 'id', values: [observableId] }, { key: 'relationship_type', values: ['has-observable'] }],
      }],
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
    // Observables are has-observable relationships: pycti adds x_observable_refs on export, the backend has no relationships to read.
    expect(stix).not.toHaveProperty('x_observable_refs');
    expect(stix.x_command_ref).toEqual(processStandardId);
    expect(stix.x_source_refs).toEqual([organizationStandardId]);
    expect(stix.platforms).toEqual(['windows']);
    expect(stix.kill_chain_phases).toEqual([{ kill_chain_name: 'mitre-attack', phase_name: 'procedure-test-phase' }]);
    expect(stix).not.toHaveProperty('x_mitre_platforms');
    expect(stix).not.toHaveProperty('x_log_source_refs');
  });

  it('reports a missing observable as a missing reference, so the import worker retries it', async () => {
    const result = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: { name: 'Procedure before its observable', procedureObservables: ['ipv4-addr--8f2b3c4d-5e6f-5a7b-9c8d-0e1f2a3b4c5d'] } },
    });
    expect(result.errors?.[0]?.extensions?.code).toBe('MISSING_REFERENCE_ERROR');
  });

  it('adds and removes observables through has-observable relationships', async () => {
    const p = await addProcedureAsAdmin({ name: 'Procedure with editable observables', procedureObservables: [observableId] });
    await queryAsAdminWithSuccess({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: p.id, toId: processId, relationship_type: 'has-observable' } },
    });
    expect((await hasObservableTargets(p.id)).sort()).toEqual([observableId, processId].sort());
    await queryAsAdminWithSuccess({
      query: RELATIONSHIP_DELETE,
      variables: { fromId: p.id, toId: observableId, relationship_type: 'has-observable' },
    });
    const procedure = await readProcedure(p.id);
    expect(procedure.procedureObservables.edges.map((e: { node: { id: string } }) => e.node.id)).toEqual([processId]);
  });

  it('creates an implements-technique relationship per technique', async () => {
    const p = await addProcedureAsAdmin({ name: 'Procedure with a technique', techniques: [attackPatternId] });
    const filters = {
      mode: 'and',
      filters: [
        { key: ['fromId'], values: [p.id] },
        { key: ['relationship_type'], values: ['implements-technique'] },
      ],
      filterGroups: [],
    };
    const result = await queryAsAdmin({ query: RELATIONSHIPS_QUERY, variables: { filters } });
    const relationships = result.data?.stixCoreRelationships.edges.map((e: { node: { from: { id: string }; to: { id: string } } }) => e.node);
    expect(relationships.length).toBe(1);
    expect(relationships[0].from.id).toBe(p.id);
    expect(relationships[0].to.id).toBe(attackPatternId);
  });

  it('computes the fingerprint on creation when none is provided', async () => {
    const p = await addProcedureAsAdmin({
      name: 'Procedure with a computed fingerprint',
      techniques: [attackPatternId],
      x_mitre_platforms: ['windows'],
      killChainPhases: [killChainPhaseId],
    });
    const procedure = await readProcedure(p.id);
    expect(procedure.x_fingerprint).toBe(computeProcedureFingerprint([attackPatternStandardId], ['windows'], ['procedure-test-phase']));
  });

  it('keeps a provided fingerprint', async () => {
    const p = await addProcedureAsAdmin({ name: 'Procedure with an imported fingerprint', techniques: [attackPatternId], x_fingerprint: 'abc' });
    const procedure = await readProcedure(p.id);
    expect(procedure.x_fingerprint).toBe('abc');
  });

  it('does not recompute the fingerprint on edit', async () => {
    const p = await addProcedureAsAdmin({ name: 'Procedure edited later', techniques: [attackPatternId], x_mitre_platforms: ['windows'] });
    const before = (await readProcedure(p.id)).x_fingerprint;
    expect(before).toBe(computeProcedureFingerprint([attackPatternStandardId], ['windows'], []));
    const patched = await queryAsAdminWithSuccess({
      query: PROCEDURE_FIELD_PATCH,
      variables: { id: p.id, input: [{ key: 'x_mitre_platforms', value: ['linux'] }] },
    });
    expect(patched.data?.procedureFieldPatch.x_fingerprint).toBe(before);
    expect((await readProcedure(p.id)).x_fingerprint).toBe(before);
  });

  it('lowercases a provided stix id', async () => {
    const stixId = 'x-opencti-procedure--5E0040B0-42DF-46D2-8E7F-0FA3D753B75E';
    const p = await addProcedureAsAdmin({ name: 'Upper case stix id', stix_id: stixId });
    expect(p.standard_id).toBe(stixId.toLowerCase());
  });

  it('deletes a procedure', async () => {
    const p = await addProcedureAsAdmin({ name: 'To delete' });
    const result = await queryAsAdmin({ query: DELETE_QUERY, variables: { id: p.id } });
    expect(result.data?.procedureDelete).toBe(p.id);
    expect(await readProcedure(p.id)).toBeNull();
  });
});

describe('Procedure components', () => {
  let procedureId: string;
  let textId: string;
  let relationshipId: string;

  beforeAll(async () => {
    procedureId = (await addProcedureAsAdmin({ name: 'Copy credential stores via wbadmin backup' })).id;
    const text = await queryAsAdminWithSuccess({ query: TEXT_ADD, variables: { Text: { value: 'start backup' } } });
    textId = text.data?.stixCyberObservableAdd.id;
  });

  afterAll(async () => {
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: procedureId } });
    await queryAsAdmin({ query: OBSERVABLE_DELETE, variables: { id: textId } });
  });

  it('refuses a secondary component at index 0', async () => {
    const result = await queryAsAdmin({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: textId, toId: procedureId, relationship_type: 'component-of', component_index: 0, component_type: 'secondary' } },
    });
    expect(result.errors?.[0]?.message).toContain('The first component must be Primary.');
  });

  it('refuses a component without an index', async () => {
    const result = await queryAsAdmin({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: textId, toId: procedureId, relationship_type: 'component-of', component_type: 'primary' } },
    });
    expect(result.errors?.length).toBeGreaterThan(0);
    expect(await componentOfRelationshipIds(procedureId)).toEqual([]);
  });

  it('creates a primary component at index 0 with its index and type', async () => {
    const created = await queryAsAdminWithSuccess({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: textId, toId: procedureId, relationship_type: 'component-of', component_index: 0, component_type: 'primary' } },
    });
    relationshipId = created.data?.stixCoreRelationshipAdd.id;
    const read = await queryAsAdmin({ query: COMPONENT_READ, variables: { id: relationshipId } });
    expect(read.data?.stixCoreRelationship.component_index).toBe(0);
    expect(read.data?.stixCoreRelationship.component_type).toBe('primary');
  });

  it('updates the index and type when the same component is added again', async () => {
    await queryAsAdminWithSuccess({
      query: RELATIONSHIP_ADD,
      variables: { input: { fromId: textId, toId: procedureId, relationship_type: 'component-of', component_index: 3, component_type: 'secondary' } },
    });
    expect(await componentOfRelationshipIds(procedureId)).toEqual([relationshipId]);
    const read = await queryAsAdmin({ query: COMPONENT_READ, variables: { id: relationshipId } });
    expect(read.data?.stixCoreRelationship.component_index).toBe(3);
    expect(read.data?.stixCoreRelationship.component_type).toBe('secondary');
  });

  it('refuses moving a secondary component to index 0', async () => {
    const result = await queryAsAdmin({
      query: RELATIONSHIP_FIELD_PATCH,
      variables: { id: relationshipId, input: [{ key: 'component_index', value: ['0'] }] },
    });
    expect(result.errors?.[0]?.message).toContain('The first component must be Primary.');
  });

  it('carries the component index and type in STIX', async () => {
    const read = await queryAsAdmin({ query: COMPONENT_READ, variables: { id: relationshipId } });
    const stix = JSON.parse(read.data?.stixCoreRelationship.toStix);
    expect(stix.x_component_index).toBe(3);
    expect(stix.x_component_type).toBe('secondary');
  });
});

describe('Procedure component sequence', () => {
  let procedureId: string;
  let malwareId: string;
  const observableIds: string[] = [];
  const sequence = (order: number[], types: string[]) => order.map((i, position) => ({ id: observableIds[i], type: types[position] }));
  const WBADMIN_TYPES = ['primary', 'primary', 'secondary', 'secondary', 'secondary'];

  beforeAll(async () => {
    procedureId = (await addProcedureAsAdmin({ name: 'Copy credential stores via wbadmin' })).id;
    const process = await queryAsAdminWithSuccess({ query: OBSERVABLE_ADD, variables: { type: 'Process', Process: { command_line: 'wbadmin.exe' } } });
    observableIds.push(process.data?.stixCyberObservableAdd.id);
    const tokens = ['start backup', '-backuptarget:\\\\127.0.0.1\\C$\\ProgramData\\', '-include:"C:\\windows\\NTDS\\ntds.dit"', '-quiet'];
    for (let i = 0; i < tokens.length; i += 1) {
      const text = await queryAsAdminWithSuccess({ query: TEXT_ADD, variables: { Text: { value: tokens[i] } } });
      observableIds.push(text.data?.stixCyberObservableAdd.id);
    }
    const malware = await queryAsAdminWithSuccess({ query: MALWARE_ADD, variables: { input: { name: 'Procedure component test malware' } } });
    malwareId = malware.data?.malwareAdd.id;
  });

  afterAll(async () => {
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: procedureId } });
    for (let i = 0; i < observableIds.length; i += 1) {
      await queryAsAdmin({ query: OBSERVABLE_DELETE, variables: { id: observableIds[i] } });
    }
    await queryAsAdmin({ query: MALWARE_DELETE, variables: { id: malwareId } });
  });

  it('saves the sequence and lists it in order with its types', async () => {
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([0, 1, 2, 3, 4], WBADMIN_TYPES) } });
    const components = await readComponents(procedureId);
    expect(components.map((c) => c.observable.id)).toEqual(observableIds);
    expect(components.map((c) => c.component_index)).toEqual([0, 1, 2, 3, 4]);
    expect(components.map((c) => c.component_type)).toEqual(WBADMIN_TYPES);
  });

  it('rewrites the indexes when the order changes, leaving no stale relationship', async () => {
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([1, 0, 2, 3, 4], WBADMIN_TYPES) } });
    const components = await readComponents(procedureId);
    expect(components.map((c) => c.observable.id)).toEqual([1, 0, 2, 3, 4].map((i) => observableIds[i]));
    expect(components.map((c) => c.component_index)).toEqual([0, 1, 2, 3, 4]);
    expect(await componentOfRelationshipIds(procedureId)).toHaveLength(5);
  });

  it('refuses a sequence that starts with a secondary component and keeps the previous one', async () => {
    const result = await queryAsAdmin({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([2, 0, 1, 3, 4], ['secondary', 'primary', 'primary', 'secondary', 'secondary']) } });
    expect(result.errors?.[0]?.message).toContain('The first component must be Primary.');
    expect((await readComponents(procedureId)).map((c) => c.observable.id)).toEqual([1, 0, 2, 3, 4].map((i) => observableIds[i]));
  });

  it('refuses an observable twice and keeps the previous sequence', async () => {
    const result = await queryAsAdmin({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([0, 1, 1], ['primary', 'primary', 'secondary']) } });
    expect(result.errors?.[0]?.message).toContain('This observable is already in the sequence.');
    expect(await readComponents(procedureId)).toHaveLength(5);
  });

  it('refuses a component that is not an observable and keeps the previous sequence', async () => {
    const result = await queryAsAdmin({ query: COMPONENTS_SET, variables: { id: procedureId, components: [{ id: observableIds[0], type: 'primary' }, { id: malwareId, type: 'secondary' }] } });
    expect(result.errors?.length).toBeGreaterThan(0);
    expect(await readComponents(procedureId)).toHaveLength(5);
  });

  it('keeps the relationships of the components it reorders', async () => {
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([0, 1, 2, 3, 4], WBADMIN_TYPES) } });
    const before = (await componentOfRelationshipIds(procedureId)).sort();
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([1, 0, 2, 4, 3], WBADMIN_TYPES) } });
    expect((await componentOfRelationshipIds(procedureId)).sort()).toEqual(before);
    const components = await readComponents(procedureId);
    expect(components.map((c) => c.observable.id)).toEqual([1, 0, 2, 4, 3].map((i) => observableIds[i]));
  });

  it('refuses to change a sequence holding a component the user cannot see', async () => {
    const hidden = await queryAsAdminWithSuccess({
      query: MARKED_TEXT_ADD,
      variables: { Text: { value: 'procedure component above the editor clearance' }, objectMarking: [MARKING_TLP_AMBER_STRICT] },
    });
    const hiddenId = hidden.data?.stixCyberObservableAdd.id;
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: [{ id: observableIds[0], type: 'primary' }, { id: hiddenId, type: 'secondary' }] } });
    const result = await queryAsUser(USER_EDITOR, { query: COMPONENTS_SET, variables: { id: procedureId, components: [{ id: observableIds[0], type: 'primary' }] } });
    expect(result.errors?.[0]?.message).toContain('This sequence holds components you cannot see.');
    expect((await readComponents(procedureId)).map((c) => c.observable.id)).toEqual([observableIds[0], hiddenId]);
    await queryAsAdmin({ query: OBSERVABLE_DELETE, variables: { id: hiddenId } });
  });

  it('keeps the other positions when a component observable is deleted', async () => {
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: sequence([0, 1, 2, 3, 4], WBADMIN_TYPES) } });
    await queryAsAdminWithSuccess({ query: OBSERVABLE_DELETE, variables: { id: observableIds[2] } });
    const components = await readComponents(procedureId);
    expect(components.map((c) => c.component_index)).toEqual([0, 1, 3, 4]);
  });

  it('empties the sequence', async () => {
    await queryAsAdminWithSuccess({ query: COMPONENTS_SET, variables: { id: procedureId, components: [] } });
    expect(await readComponents(procedureId)).toEqual([]);
    expect(await componentOfRelationshipIds(procedureId)).toEqual([]);
  });
});
