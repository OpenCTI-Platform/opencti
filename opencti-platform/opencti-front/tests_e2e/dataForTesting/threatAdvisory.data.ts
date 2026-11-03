import { APIRequestContext, PlaywrightWorkerArgs } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import { executeGraphql } from './query-utils';
import { authenticateAdminApi } from './session.data';

type Playwright = PlaywrightWorkerArgs['playwright'];

export const THREAT_ADVISORY_FORM_NAME = 'Threat Advisories';

export const PERSONAS = {
  analystOrgA: { email: 'analystorga@filigran.test', password: 'analystorga' },
  managerOrgA: { email: 'managerorga@filigran.test', password: 'managerorga' },
  analystOrgB: { email: 'analystorgb@filigran.test', password: 'analystorgb' },
  managerOrgB: { email: 'managerorgb@filigran.test', password: 'managerorgb' },
  analystOrgC: { email: 'analystorgc@filigran.test', password: 'analystorgc' },
  managerOrgC: { email: 'managerorgc@filigran.test', password: 'managerorgc' },
};

export type Persona = typeof PERSONAS[keyof typeof PERSONAS];

export type DraftStatus = 'NEW' | 'MO MANAGER REVIEW' | 'ORGC ANALYST REVIEW' | 'ORGC MANAGER REVIEW';

/** The sync transitions between statuses, each fired by the persona that owns it (happy-flow steps 5, 8 and 11). */
const TRANSITIONS: { persona: Persona; event: string; status: DraftStatus }[] = [
  { persona: PERSONAS.analystOrgA, event: 'Request MO manager review', status: 'MO MANAGER REVIEW' },
  { persona: PERSONAS.managerOrgA, event: 'Send to OrgC for review', status: 'ORGC ANALYST REVIEW' },
  { persona: PERSONAS.analystOrgC, event: 'SEND TO ORGC MANAGER', status: 'ORGC MANAGER REVIEW' },
];

/**
 * The login mutation is rate limited to one call per second (`@rateLimit(limit: 1, duration: 1)`),
 * platform-wide: a login that lands within a second of another one is refused, so retry it.
 */
const withLoginRateLimit = (login: () => Promise<unknown>) => expect(async () => {
  await login();
}).toPass({ timeout: 60000, intervals: [1100] });

/**
 * An API session of its own, logged in as the persona: no browser, no shared cookie jar. The draft
 * context sticks to the user, so a persona a previous UI session left inside a draft is taken out of
 * it first (like the UI does after login): creating or moving drafts from inside one fails.
 */
const loginApi = async (playwright: Playwright, baseURL: string, persona: Persona): Promise<APIRequestContext> => {
  const api = await playwright.request.newContext({ baseURL, ignoreHTTPSErrors: true });
  await withLoginRateLimit(() => executeGraphql(
    api,
    `Log in ${persona.email}`,
    'mutation PersonaLogin($input: UserLoginInput!) { token(input: $input) }',
    { input: { email: persona.email, password: persona.password } },
  ));
  await executeGraphql(
    api,
    `Leave the draft context of ${persona.email}`,
    'mutation PersonaExitDraft($input: [EditInput]!) { meEdit(input: $input) { id } }',
    { input: [{ key: 'draft_context', value: [''] }] },
  );
  return api;
};

interface DraftState {
  status: string | null;
  pending: string | null;
  containers: number;
  processing: number;
}

const readDraft = async (api: APIRequestContext, draftId: string): Promise<DraftState> => {
  const { draftWorkspace } = await executeGraphql<{
    draftWorkspace: {
      processingCount: number;
      objectsCount: { containersCount: number };
      workflowInstance: { pendingStatus: string | null; currentStatus: { template: { name: string } } | null } | null;
    };
  }>(
    api,
    'Read the draft',
    `query PersonaDraft($id: String!) {
      draftWorkspace(id: $id) {
        processingCount
        objectsCount { containersCount }
        workflowInstance { pendingStatus currentStatus { template { name } } }
      }
    }`,
    { id: draftId },
  );
  return {
    status: draftWorkspace.workflowInstance?.currentStatus?.template.name.toUpperCase() ?? null,
    pending: draftWorkspace.workflowInstance?.pendingStatus ?? null,
    containers: draftWorkspace.objectsCount.containersCount,
    processing: draftWorkspace.processingCount,
  };
};

/**
 * Submits the Threat Advisories form as AnalystOrgA, through the API, and returns the draft id once
 * the draft is at status NEW with its Report ingested. Same submission as the UI's (`FormView.tsx`):
 * a draft, with the form's own defaults for the author and the authorized members.
 */
export const submitThreatAdvisoryDraftViaApi = async (playwright: Playwright, baseURL: string, reportName: string): Promise<string> => {
  const admin = await playwright.request.newContext({ baseURL, ignoreHTTPSErrors: true });
  const analyst = await loginApi(playwright, baseURL, PERSONAS.analystOrgA);
  try {
    await withLoginRateLimit(() => authenticateAdminApi(admin));
    const { forms } = await executeGraphql<{ forms: { edges: { node: { id: string; name: string; form_schema: string } }[] } }>(
      admin,
      'Find the Threat Advisories form',
      'query PersonaForms($search: String) { forms(search: $search, first: 10) { edges { node { id name form_schema } } } }',
      { search: THREAT_ADVISORY_FORM_NAME },
    );
    const form = forms.edges.map(({ node }) => node).find(({ name }) => name === THREAT_ADVISORY_FORM_NAME);
    if (!form) throw new Error(`The "${THREAT_ADVISORY_FORM_NAME}" form intake does not exist: run the form intake setup first`);
    const { organizations } = await executeGraphql<{ organizations: { edges: { node: { id: string; name: string } }[] } }>(
      admin,
      'Find OrgA',
      'query PersonaOrganizations($search: String) { organizations(search: $search, first: 10) { edges { node { id name } } } }',
      { search: 'OrgA' },
    );
    const orgA = organizations.edges.map(({ node }) => node).find(({ name }) => name === 'OrgA');
    if (!orgA) throw new Error('OrgA does not exist');
    // Same values as the UI sends: the form's fields (name, published, createdBy) by field name, and
    // the draft's authorized members from the form's own defaults.
    const schema = JSON.parse(form.form_schema) as { draftDefaults?: { authorizedMembers?: { defaults?: unknown[] } } };
    const values = {
      name: reportName,
      published: new Date().toISOString(),
      createdBy: orgA.id,
      draftAuthorizedMembers: schema.draftDefaults?.authorizedMembers?.defaults ?? [],
    };
    const { formSubmit } = await executeGraphql<{ formSubmit: { success: boolean; message: string | null; entityId: string | null } }>(
      analyst,
      'Submit the Threat Advisories form',
      `mutation PersonaFormSubmit($input: FormSubmissionInput!, $isDraft: Boolean!) {
        formSubmit(input: $input, isDraft: $isDraft) { success message entityId }
      }`,
      { input: { formId: form.id, values: JSON.stringify(values) }, isDraft: true },
    );
    if (!formSubmit.success || !formSubmit.entityId) {
      throw new Error(`Submit the Threat Advisories form failed: ${formSubmit.message ?? 'no draft id'}`);
    }
    const draftId = formSubmit.entityId;
    await expect.poll(() => readDraft(analyst, draftId), {
      message: 'Expected the new draft to be NEW, with its Report ingested',
      timeout: 90000,
    }).toMatchObject({ status: 'NEW', pending: null, containers: 1, processing: 0 });
    return draftId;
  } finally {
    await admin.dispose();
    await analyst.dispose();
  }
};

/** Moves a NEW draft to `target` through the API, each transition fired by its own persona (the same hops as the UI flow). */
export const advanceDraftViaApi = async (playwright: Playwright, baseURL: string, draftId: string, target: Exclude<DraftStatus, 'NEW'>) => {
  for (const { persona, event, status } of TRANSITIONS) {
    const api = await loginApi(playwright, baseURL, persona);
    try {
      const { triggerWorkflowEvent } = await executeGraphql<{ triggerWorkflowEvent: { success: boolean; reason: string | null } }>(
        api,
        `Trigger "${event}" as ${persona.email}`,
        `mutation PersonaTransition($entityId: String!, $eventName: String!) {
          triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) { success reason }
        }`,
        { entityId: draftId, eventName: event },
      );
      if (!triggerWorkflowEvent.success) {
        throw new Error(`Trigger "${event}" as ${persona.email} failed: ${triggerWorkflowEvent.reason ?? 'no reason'}`);
      }
      await expect.poll(async () => {
        const { status: current, pending } = await readDraft(api, draftId);
        return { status: current, pending };
      }, {
        message: `Expected the draft to reach ${status} after "${event}"`,
        timeout: 60000,
      }).toEqual({ status, pending: null });
    } finally {
      await api.dispose();
    }
    if (status === target) return;
  }
};

/**
 * Waits for the "Report created" playbook to have applied the final authorized members (OrgC
 * manages) on the validated Report, so the per-persona access checks never race it. Returns nothing.
 */
export const waitForReportAccessApplied = async (playwright: Playwright, baseURL: string, reportName: string) => {
  const admin = await playwright.request.newContext({ baseURL, ignoreHTTPSErrors: true });
  try {
    await withLoginRateLimit(() => authenticateAdminApi(admin));
    await expect.poll(async () => {
      const { reports } = await executeGraphql<{ reports: { edges: { node: { authorized_members: { name: string; access_right: string }[] | null } }[] } }>(
        admin,
        'Read the validated Report access',
        `query PersonaReport($search: String) {
          reports(search: $search, first: 5) { edges { node { authorized_members { name access_right } } } }
        }`,
        { search: `"${reportName}"` },
      );
      const members = reports.edges[0]?.node.authorized_members ?? [];
      return members.some(({ name, access_right }) => name === 'OrgC' && access_right === 'admin');
    }, {
      message: 'Expected the playbook to give OrgC manage access on the validated Report',
      timeout: 120000,
    }).toBe(true);
  } finally {
    await admin.dispose();
  }
};
