import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_API_TOKEN,
  ADMIN_USER,
  getUserIdByEmail,
  queryInitPlatformAsTokenBearer,
  queryInitPlatformAsUser,
  testContext,
  USER_EDITOR,
  USER_FORM_INTAKE,
  USER_PARTICIPATE,
  type UserTestData,
} from '../../utils/testQuery';
import { awaitUntilCondition, queryAsAdminWithSuccess, queryAsUser, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { redisGetWork } from '../../../src/database/redis';
import { connectorIdFromIngestId, unregisterConnectorForIngestion } from '../../../src/domain/connector';
import { deleteWork, worksForConnector } from '../../../src/domain/work';
import { createWorkForBackgroundTask } from '../../../src/domain/backgroundTask-common';
import { getBestBackgroundConnectorId } from '../../../src/database/rabbitmq';
import { addRole, addGroup } from '../../../src/domain/grant';
import { groupAddRelation, groupDelete } from '../../../src/domain/group';
import { addUser, roleAddRelation, roleCapabilities, roleDelete, roleDeleteRelation, userDelete } from '../../../src/modules/user/user-domain';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../../../src/schema/internalObject';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../../../src/schema/internalRelationship';
import { generateStandardId } from '../../../src/schema/identifier';
import { FORBIDDEN_ACCESS } from '../../../src/config/errors';
import type { BasicStoreEntity, BasicCapabilityEntity } from '../../../src/types/store';
import { up as addFormIntakeCapabilityMigration } from '../../../src/migrations/1791560871501-add-form-intake-capability';

const FORM_CAPABILITY = 'KNOWLEDGE_KNFORMINTAKE';

const FORM_ADD_QUERY = gql`
  mutation FormAdd($input: FormAddInput!) {
    formAdd(input: $input) {
      id
    }
  }
`;
const FORM_DELETE_QUERY = gql`
  mutation FormDelete($id: ID!) {
    formDelete(id: $id)
  }
`;
const FORMS_QUERY = gql`
  query Forms($first: Int) {
    forms(first: $first) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;
const FORM_QUERY = gql`
  query Form($id: ID!) {
    form(id: $id) {
      id
      name
    }
  }
`;
const FORM_SUBMIT_QUERY = gql`
  mutation FormSubmit($input: FormSubmissionInput!, $isDraft: Boolean!) {
    formSubmit(input: $input, isDraft: $isDraft) {
      success
      bundleId
      entityId
    }
  }
`;
const REPORT_ADD_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;
const MALWARE_ADD_QUERY = gql`
  mutation MalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) {
      id
      name
      creators {
        id
      }
    }
  }
`;
const MALWARE_DELETE_QUERY = gql`
  mutation MalwareDelete($id: ID!) {
    malwareEdit(id: $id) {
      delete
    }
  }
`;
const MALWARES_SEARCH_QUERY = gql`
  query MalwaresSearch($search: String) {
    malwares(search: $search) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;
const DRAFT_ADD_QUERY = gql`
  mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
    }
  }
`;
const DRAFT_DELETE_QUERY = gql`
  mutation DraftWorkspaceDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;

const FORM_SCHEMA = {
  version: '1.0',
  mainEntityType: 'Malware',
  includeInContainer: false,
  fields: [{
    id: 'name',
    name: 'name',
    label: 'Name',
    type: 'text',
    required: true,
    attributeMapping: { entity: 'main_entity', attributeName: 'name' },
  }],
  additionalEntities: [],
  relationships: [],
};

// Every id created by the tests, cleaned in afterAll whatever happens
const KILL_CHAIN_PHASE_ADD_QUERY = gql`
  mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) {
      id
      x_opencti_order
    }
  }
`;
const KILL_CHAIN_PHASE_DELETE_QUERY = gql`
  mutation KillChainPhaseDelete($id: ID!) {
    killChainPhaseEdit(id: $id) {
      delete
    }
  }
`;

const createdMalwareIds: string[] = [];
const createdKillChainPhaseIds: string[] = [];
const createdWorkIds: string[] = [];
const createdDraftIds: string[] = [];
const createdUserIds: string[] = [];
const createdGroupIds: string[] = [];
const createdRoleIds: string[] = [];

let formId: string;
let formOnlyUserId: string;

// A role created on the fly. The draft capabilities go through relations: addRole does not take them as an input.
const createRole = async (name: string, capabilities: string[], capabilitiesInDraft: string[] = []) => {
  const role = await addRole(testContext, ADMIN_USER, { name, description: name, capabilities });
  createdRoleIds.push(role.id);
  for (const capability of capabilitiesInDraft) {
    const toId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capability });
    await roleAddRelation(testContext, ADMIN_USER, role.id, { toId, relationship_type: RELATION_HAS_CAPABILITY_IN_DRAFT });
  }
  return role;
};

// A user created on the fly, with its own role (and group), by the domain API.
const createDynamicUser = async (name: string, capabilities: string[], capabilitiesInDraft: string[] = []): Promise<UserTestData> => {
  const role = await createRole(name, [...capabilities, 'APIACCESS_USEBASICAUTH'], capabilitiesInDraft);
  const group = await addGroup(testContext, ADMIN_USER, { name, description: name });
  createdGroupIds.push(group.id);
  await groupAddRelation(testContext, ADMIN_USER, group.id, { toId: role.id, relationship_type: 'has-role' });
  const user = await addUser(testContext, ADMIN_USER, {
    user_email: `${name}@opencti.io`,
    name,
    password: name,
    groups: [group.id],
    prevent_default_groups: true,
  });
  createdUserIds.push(user.id);
  return { id: user.id, email: `${name}@opencti.io`, password: name, groups: [] };
};

const formWorkIds = async () => {
  const works = await worksForConnector(testContext, ADMIN_USER, connectorIdFromIngestId(formId), { first: 100 }) as { internal_id: string }[];
  return works.map((work) => work.internal_id);
};

const submitForm = (user: UserTestData, isDraft: boolean, values: Record<string, unknown> = { name: 'Form intake IT malware' }) => {
  return queryAsUser(user, { query: FORM_SUBMIT_QUERY, variables: { input: { formId, values: JSON.stringify(values) }, isDraft } });
};

// Submit a form and return the work it created (its Redis state is the binding the import is checked against)
const submitFormWithSuccess = async (user: UserTestData, isDraft: boolean, values?: Record<string, unknown>) => {
  const before = await formWorkIds();
  const result = await submitForm(user, isDraft, values);
  expect(result.errors, JSON.stringify(result.errors)).toBeUndefined();
  expect((result.data as any).formSubmit.success).toBe(true);
  let workId = '';
  await awaitUntilCondition(async () => {
    workId = (await formWorkIds()).find((id) => !before.includes(id)) ?? '';
    return workId !== '';
  }, 15000, { message: 'the work of the form submission was not created' });
  createdWorkIds.push(workId);
  const draftId = (result.data as any).formSubmit.entityId as string;
  if (isDraft) createdDraftIds.push(draftId);
  return { workId, draftId };
};

// What the python worker does: the platform credential, impersonating the applicant, in the context of the work
type WorkerOptions = { workId?: string; applicantId?: string; draftId?: string };
const callWithWorkerHeaders = async (name: string, options: WorkerOptions, token = ADMIN_API_TOKEN) => {
  try {
    return await queryInitPlatformAsTokenBearer(token, MALWARE_ADD_QUERY, { input: { name } }, options);
  } catch (error: any) {
    // errors raised while building the request context (e.g. a dead work) come with an http status
    return error.response?.data ?? { errors: [{ message: error.message }] };
  }
};
const expectForbidden = (result: any) => {
  expect(result.errors, JSON.stringify(result)).toBeDefined();
  expect(result.errors[0].extensions?.code ?? result.errors[0].name).toBe(FORBIDDEN_ACCESS);
  expect(result.data?.malwareAdd).toBeFalsy();
};
const expectWorkNotAlive = (result: any) => {
  expect(result.errors, JSON.stringify(result)).toBeDefined();
  expect(result.errors[0].extensions?.code ?? result.errors[0].name).toBe('WORK_NOT_ALIVE');
  expect(result.data?.malwareAdd).toBeFalsy();
};
const searchMalware = async (name: string) => {
  const { data } = await queryAsAdminWithSuccess({ query: MALWARES_SEARCH_QUERY, variables: { search: `"${name}"` } });
  return data.malwares.edges as { node: { id: string } }[];
};

beforeAll(async () => {
  const { data } = await queryAsAdminWithSuccess({
    query: FORM_ADD_QUERY,
    variables: { input: { name: 'Form intake IT form', description: 'integration test', form_schema: JSON.stringify(FORM_SCHEMA), active: true } },
  });
  formId = data.formAdd.id;
  // The submissions of these tests only need their work (the binding the import is checked against), the worker is
  // simulated with headers. A real worker (the CI one) would import the queued bundles later and at any time, and leave
  // objects that change the counts of other tests: nothing listens to the queue of a form whose connector is unregistered.
  await unregisterConnectorForIngestion(testContext, formId);
  formOnlyUserId = await getUserIdByEmail(USER_FORM_INTAKE.email);
});

afterAll(async () => {
  for (const id of createdMalwareIds) await queryAsAdminWithSuccess({ query: MALWARE_DELETE_QUERY, variables: { id } }).catch(() => {});
  for (const id of createdKillChainPhaseIds) await queryAsAdminWithSuccess({ query: KILL_CHAIN_PHASE_DELETE_QUERY, variables: { id } }).catch(() => {});
  for (const id of createdWorkIds) await deleteWork(testContext, ADMIN_USER, id).catch(() => {});
  for (const id of createdDraftIds) await queryAsAdminWithSuccess({ query: DRAFT_DELETE_QUERY, variables: { id } }).catch(() => {});
  if (formId) await queryAsAdminWithSuccess({ query: FORM_DELETE_QUERY, variables: { id: formId } }).catch(() => {});
  for (const id of createdUserIds) await userDelete(testContext, ADMIN_USER, id).catch(() => {});
  for (const id of createdGroupIds) await groupDelete(testContext, ADMIN_USER, id).catch(() => {});
  for (const id of createdRoleIds) await roleDelete(testContext, ADMIN_USER, id).catch(() => {});
});

describe('Form-only user (only the Form Intake capability)', () => {
  it('should be allowed to list and read forms', async () => {
    const list = await queryAsUserWithSuccess(USER_FORM_INTAKE, { query: FORMS_QUERY, variables: { first: 50 } });
    expect(list.data.forms.edges.map((edge: any) => edge.node.id)).toContain(formId);
    const read = await queryAsUserWithSuccess(USER_FORM_INTAKE, { query: FORM_QUERY, variables: { id: formId } });
    expect(read.data.form.id).toEqual(formId);
  });

  it('should not be allowed to create knowledge directly', async () => {
    await queryAsUserIsExpectedForbidden(USER_FORM_INTAKE, {
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'Direct report', published: '2026-01-01T00:00:00.000Z' } },
    });
    await queryAsUserIsExpectedForbidden(USER_FORM_INTAKE, { query: MALWARE_ADD_QUERY, variables: { input: { name: 'Direct malware' } } });
  });
});

describe('Form submission by a form-only user, imported by the worker on its behalf', () => {
  let mainWork: { workId: string };
  let draftWork: { workId: string; draftId: string };

  it('should submit a form to the main destination and bind the work to the submission', async () => {
    mainWork = await submitFormWithSuccess(USER_FORM_INTAKE, false);
    const work = await redisGetWork(mainWork.workId);
    expect(work.is_initialized).toEqual('true');
    expect(work.form_applicant_id).toEqual(formOnlyUserId);
    expect(work.form_id).toEqual(formId);
    expect(work.form_draft_id).toEqual('');
  });

  it('should submit a form to a draft and bind the work to the draft', async () => {
    draftWork = await submitFormWithSuccess(USER_FORM_INTAKE, true);
    const work = await redisGetWork(draftWork.workId);
    expect(work.form_applicant_id).toEqual(formOnlyUserId);
    expect(work.form_id).toEqual(formId);
    expect(work.form_draft_id).toEqual(draftWork.draftId);
  });

  it('should let the worker create knowledge as the applicant in the main destination', async () => {
    const name = 'Form intake IT worker malware';
    const result = await callWithWorkerHeaders(name, { workId: mainWork.workId, applicantId: formOnlyUserId });
    expect(result.errors, JSON.stringify(result)).toBeUndefined();
    createdMalwareIds.push(result.data.malwareAdd.id);
    expect(result.data.malwareAdd.name).toEqual(name);
    expect(result.data.malwareAdd.creators.map((creator: { id: string }) => creator.id)).toEqual([formOnlyUserId]);
  });

  it('should let the worker create knowledge as the applicant in the draft of the submission', async () => {
    const name = 'Form intake IT worker draft malware';
    const result = await callWithWorkerHeaders(name, { workId: draftWork.workId, applicantId: formOnlyUserId, draftId: draftWork.draftId });
    expect(result.errors, JSON.stringify(result)).toBeUndefined();
    expect(result.data.malwareAdd.creators.map((creator: { id: string }) => creator.id)).toEqual([formOnlyUserId]);
    // the draft is deleted in afterAll, with what it holds
  });

  // The worker upserts the kill chain phases of the objects it imports: attaching an existing one needs no right to manage them
  it('should let the worker attach an existing kill chain phase as the applicant, but not create one', async () => {
    const phase = { kill_chain_name: 'form-intake-it', phase_name: 'existing', x_opencti_order: 1 };
    const { data } = await queryAsAdminWithSuccess({ query: KILL_CHAIN_PHASE_ADD_QUERY, variables: { input: phase } });
    createdKillChainPhaseIds.push(data.killChainPhaseAdd.id);
    const worker = { workId: mainWork.workId, applicantId: formOnlyUserId };
    const upsert = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, KILL_CHAIN_PHASE_ADD_QUERY, { input: { ...phase, x_opencti_order: 7, update: true } }, worker);
    expect(upsert.errors, JSON.stringify(upsert)).toBeUndefined();
    expect(upsert.data.killChainPhaseAdd).toEqual({ id: data.killChainPhaseAdd.id, x_opencti_order: 1 });
    const create = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, KILL_CHAIN_PHASE_ADD_QUERY, { input: { ...phase, phase_name: 'new' } }, worker);
    expect(create.errors?.[0].extensions?.code, JSON.stringify(create)).toBe(FORBIDDEN_ACCESS);
  });

  describe('forged attempts', () => {
    it('should reject the form-only user own credential with the worker headers', async () => {
      const name = 'Form intake IT forged own credential';
      let result: any;
      try {
        result = await queryInitPlatformAsUser(USER_FORM_INTAKE, MALWARE_ADD_QUERY, { input: { name } }, { workId: mainWork.workId, applicantId: formOnlyUserId });
      } catch (error: any) {
        result = error.response?.data;
      }
      expectForbidden(result);
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject an applicant that is not the one of the work', async () => {
      const name = 'Form intake IT forged applicant';
      const participantId = await getUserIdByEmail(USER_PARTICIPATE.email);
      expectForbidden(await callWithWorkerHeaders(name, { workId: mainWork.workId, applicantId: participantId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject the work of another applicant', async () => {
      const name = 'Form intake IT forged other applicant work';
      const editorWork = await submitFormWithSuccess(USER_EDITOR, false);
      expectForbidden(await callWithWorkerHeaders(name, { workId: editorWork.workId, applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject a request without work id', async () => {
      const name = 'Form intake IT forged no work';
      expectForbidden(await callWithWorkerHeaders(name, { applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject a work id that does not exist', async () => {
      const name = 'Form intake IT forged wrong work';
      expectWorkNotAlive(await callWithWorkerHeaders(name, { workId: 'work_00000000-0000-0000-0000-000000000000', applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject a draft header on the work of a main submission', async () => {
      const name = 'Form intake IT forged draft on main work';
      expectForbidden(await callWithWorkerHeaders(name, { workId: mainWork.workId, applicantId: formOnlyUserId, draftId: draftWork.draftId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject the work of a draft submission without the draft header', async () => {
      const name = 'Form intake IT forged no draft on draft work';
      expectForbidden(await callWithWorkerHeaders(name, { workId: draftWork.workId, applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject the work of a draft submission with the header of another draft', async () => {
      const name = 'Form intake IT forged other draft';
      const { data } = await queryAsAdminWithSuccess({ query: DRAFT_ADD_QUERY, variables: { input: { name: 'Form intake IT other draft' } } });
      createdDraftIds.push(data.draftWorkspaceAdd.id);
      expectForbidden(await callWithWorkerHeaders(name, { workId: draftWork.workId, applicantId: formOnlyUserId, draftId: data.draftWorkspaceAdd.id }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject a work that is not a form submission', async () => {
      const name = 'Form intake IT forged other kind of work';
      const connectorId = await getBestBackgroundConnectorId(testContext, ADMIN_USER);
      const otherWork = (await createWorkForBackgroundTask(testContext, 'form-intake-it-task', connectorId))!;
      createdWorkIds.push(otherWork.id);
      expectForbidden(await callWithWorkerHeaders(name, { workId: otherWork.id, applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });

    it('should reject the work of a submission once it is deleted', async () => {
      const name = 'Form intake IT forged dead work';
      const { workId } = await submitFormWithSuccess(USER_FORM_INTAKE, false);
      await deleteWork(testContext, ADMIN_USER, workId);
      expectWorkNotAlive(await callWithWorkerHeaders(name, { workId, applicantId: formOnlyUserId }));
      expect(await searchMalware(name)).toHaveLength(0);
    });
  });
});

describe('Pending labels in a form submission', () => {
  const withLabel = { name: 'Form intake IT label malware', pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: 'form-intake-it-label' } }] };

  it('should reject a pending label without the right to create labels', async () => {
    const before = await formWorkIds();
    await queryAsUserIsExpectedForbidden(USER_FORM_INTAKE, {
      query: FORM_SUBMIT_QUERY,
      variables: { input: { formId, values: JSON.stringify(withLabel) }, isDraft: false },
    });
    expect(await formWorkIds()).toEqual(before);
  });

  it('should accept a pending label with the right to create labels', async () => {
    const labelManager = await createDynamicUser('formintakelabel', [FORM_CAPABILITY, 'SETTINGS_SETLABELS']);
    await submitFormWithSuccess(labelManager, false, withLabel);
  });
});

describe('Destination of a form submission', () => {
  it('should not let a capability granted only in draft submit to the main destination', async () => {
    const draftOnly = await createDynamicUser('formintakedraft', [], [FORM_CAPABILITY]);
    const before = await formWorkIds();
    const refused = await submitForm(draftOnly, false);
    expect(refused.errors?.[0].extensions?.code).toEqual(FORBIDDEN_ACCESS);
    expect(await formWorkIds()).toEqual(before);
    // but a draft is accepted
    const { workId, draftId } = await submitFormWithSuccess(draftOnly, true);
    const work = await redisGetWork(workId);
    expect(work.form_applicant_id).toEqual(draftOnly.id);
    expect(work.form_draft_id).toEqual(draftId);
  });
});

describe('Migration add-form-intake-capability', () => {
  const rolesHolding = async (relationshipType: string) => {
    const roles = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_ROLE]);
    const holders: string[] = [];
    for (const role of roles) {
      const capabilities = await roleCapabilities(testContext, ADMIN_USER, role.id, relationshipType) as BasicCapabilityEntity[];
      if (capabilities.some((capability) => capability.name === FORM_CAPABILITY)) holders.push(role.id);
    }
    return holders.sort();
  };

  it('should grant the form capability in each scope where a role has Create / Update knowledge', async () => {
    const mainOnly = await createRole('mig main', ['KNOWLEDGE_KNUPDATE']);
    const draftOnly = await createRole('mig draft', [], ['KNOWLEDGE_KNUPDATE']);
    const both = await createRole('mig both', ['KNOWLEDGE_KNUPDATE'], ['KNOWLEDGE_KNUPDATE']);
    const none = await createRole('mig none', ['KNOWLEDGE_KNPARTICIPATE'], ['KNOWLEDGE_KNPARTICIPATE']);
    const mainBefore = await rolesHolding(RELATION_HAS_CAPABILITY);
    const draftBefore = await rolesHolding(RELATION_HAS_CAPABILITY_IN_DRAFT);

    await addFormIntakeCapabilityMigration(() => {});
    // running it again changes nothing
    await addFormIntakeCapabilityMigration(() => {});

    const mainAfter = await rolesHolding(RELATION_HAS_CAPABILITY);
    const draftAfter = await rolesHolding(RELATION_HAS_CAPABILITY_IN_DRAFT);
    try {
      expect(mainAfter).toContain(mainOnly.id);
      expect(mainAfter).toContain(both.id);
      expect(mainAfter).not.toContain(draftOnly.id);
      expect(mainAfter).not.toContain(none.id);
      expect(draftAfter).toContain(draftOnly.id);
      expect(draftAfter).toContain(both.id);
      expect(draftAfter).not.toContain(mainOnly.id);
      expect(draftAfter).not.toContain(none.id);
    } finally {
      // put back the roles of the test platform in the state they were
      const capabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: FORM_CAPABILITY });
      for (const roleId of mainAfter.filter((id) => !mainBefore.includes(id))) {
        await roleDeleteRelation(testContext, ADMIN_USER, roleId, capabilityId, RELATION_HAS_CAPABILITY);
      }
      for (const roleId of draftAfter.filter((id) => !draftBefore.includes(id))) {
        await roleDeleteRelation(testContext, ADMIN_USER, roleId, capabilityId, RELATION_HAS_CAPABILITY_IN_DRAFT);
      }
    }
  });
});
