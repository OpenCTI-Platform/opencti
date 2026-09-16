import { expect } from 'vitest';
import readline from 'node:readline';
import fs from 'node:fs';
import Upload from 'graphql-upload/Upload.mjs';
import { ApolloServer } from '@apollo/server';
import createSchema from '../../src/graphql/schema';
import { downloadFile } from '../../src/database/raw-file-storage';
import { streamConverter } from '../../src/database/file-storage';
import { wait } from '../../src/database/utils';
import { logApp } from '../../src/config/conf';
import { AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../../src/config/errors';
import { getSettings, settingsEditField } from '../../src/domain/settings';
import { fileToReadStream } from '../../src/database/file-storage';
import { resetCacheForEntity } from '../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../src/schema/internalObject';
import type { AuthContext, AuthUser } from '../../src/types/user';
import { computeLoaders } from '../../src/http/httpAuthenticatedContext';
import { executionContext } from '../../src/utils/access';
import { ADMIN_USER, getAuthUser, getOrganizationIdByName, type OrganizationTestData, testContext, type UserTestData } from './testQuery';

type Request = { query: any; variables?: any };

// ------------------------------------------------------------------------------
// Helpers/utilities for integration test case usage.
//
// These helpers trigger a request directly on a light-weight Apollo Server,
// shunting the entire Express middleware logic.
// Should be called in test cases only, not during the globalSetup phase.
// The good sides :
// - it makes it easy and fast to test resolvers
// - handlers participate in code coverage
// The sides to improve:
// - middleware logic is not included which makes it impossible to test some
// use cases correctly. For those you can fall back to using the
// `queryInitPlatform...` helpers in `testQuery.ts` for now. We're working on
// improving the setup in order to unify the experience while remaining able
// to track coverage.
// Note: vitest cannot be an import of testQuery, so it must be a separate file.
// ------------------------------------------------------------------------------

/**
 * Test utility.
 * Execute the query and verify that there is no error before returning result.
 * @param request
 */
export const queryAsAdminWithSuccess = async (request: Request) => {
  const requestResult = await queryAsAdmin({
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  if (requestResult.errors) {
    logApp.info('Unexpected error; requestResult:', { requestResult });
  }
  expect(requestResult.errors, `This errors should not be there: ${JSON.stringify(requestResult.errors)}`).toBeUndefined();
  expect(requestResult.data, 'No data in succesful response').toBeDefined();
  return {
    data: requestResult.data!,
  };
};

export const queryAsAdminWithError = async (
  request: Request,
  errorMessage?: string,
  errorName?: string,
) => {
  const requestResult = await queryAsAdmin({
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  expect(requestResult.errors?.length).toEqual(1);
  if (errorMessage) {
    expect(requestResult.errors?.[0].message, `error message: ${errorMessage} is expected, but got ${requestResult.errors?.[0].message}`).toBe(errorMessage);
  }
  if (errorName) {
    expect(requestResult.errors?.[0].extensions?.code, `error is expected but got ${requestResult.errors?.[0].extensions?.code}`).toBe(errorName);
  }
  return requestResult;
};

/**
 * Execute the query as some User, and verify success and return query result.
 * @param testUser
 * @param request
 */
export const queryAsUserWithSuccess = async (testUser: UserTestData, request: Request) => {
  const requestResult = await queryAsTestUser(testUser, {
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  if (requestResult.errors) {
    logApp.error('Unexpected error; request:', { request, requestResult });
  }
  expect(requestResult.errors, `This errors should not be there: ${JSON.stringify(requestResult.errors)}`).toBeUndefined();
  expect(requestResult.data, 'No data in succesful response').toBeDefined();
  return {
    data: requestResult.data!,
  };
};

/**
 * Execute the query as some User, and just return response (no validation).
 * @param testUser
 * @param request
 */
export const queryAsUser = async (testUser: UserTestData, request: Request) => {
  const requestResult = await queryAsTestUser(testUser, {
    query: request.query,
    variables: request.variables,
  });
  return requestResult;
};

/**
 * Execute the query as some User (see testQuery.ts), and verify that access is forbidden.
 * @param testUser
 * @param request
 */
export const queryAsUserIsExpectedForbidden = async (testUser: UserTestData, request: Request, message?: string) => {
  const queryResult = await queryAsTestUser(testUser, {
    query: request.query,
    variables: request.variables,
  });
  logApp.info('queryAsUserIsExpectedForbidden=> queryResult:', queryResult);
  expect(queryResult.errors, 'FORBIDDEN_ACCESS is expected.').toBeDefined();
  expect(queryResult.errors?.length, message ?? `FORBIDDEN_ACCESS is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  expect(queryResult.errors?.[0].extensions?.code, `FORBIDDEN_ACCESS is expected but got ${queryResult.errors?.[0].extensions?.code}`).toBe(FORBIDDEN_ACCESS);
};

/**
 * Execute the query as some User (see testQuery.ts), and verify that error is thrown.
 * @param testUser
 * @param request
 * @param errorMessage
 * @param errorName
 */
export const queryAsUserIsExpectedError = async (testUser: UserTestData, request: Request, errorMessage?: string, errorName?: string) => {
  const queryResult = await queryAsTestUser(testUser, {
    query: request.query,
    variables: request.variables,
  });
  logApp.info('queryAsUserIsExpectedError=> queryResult:', queryResult);
  expect(queryResult.errors, 'error is expected.').toBeDefined();
  expect(queryResult.errors?.length, `1 error is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  if (errorMessage) {
    expect(queryResult.errors?.[0].message, `error message: ${errorMessage} is expected, but got ${queryResult.errors?.[0].message}`).toBe(errorMessage);
  }
  if (errorName) {
    expect(queryResult.errors?.[0].extensions?.code, `error is expected but got ${queryResult.errors?.[0].extensions?.code}`).toBe(errorName);
  }
};

/**
 * Call a graphQL request with no authentication / no login and verify that access is forbidden.
 * @param request
 */
export const queryUnauthenticatedIsExpectedForbidden = async (request: Request) => {
  const queryResult = await queryAsAnonymous({
    query: request.query,
    variables: request.variables,
  });
  expect(queryResult.errors, 'AUTH_REQUIRED error is expected but got zero errors.').toBeDefined();
  expect(queryResult.errors?.length, `AUTH_REQUIRED is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  expect(queryResult.errors?.[0].extensions?.code, `AUTH_REQUIRED is expected but got ${queryResult.errors?.[0].extensions?.code}`).toBe(AUTH_REQUIRED);
};

/**
 * Execute a query as an anonymous user (so no user in execution context)
 * @param request
 * @param draftContext
 */
export const queryAsAnonymous = async <T = Record<string, any>>(request: Request, draftContext?: any) => {
  return query<T>({ user: undefined, request, draftContext });
};

/**
 * Execute a query as an admin
 * @param request
 * @param draftContext
 */
export const queryAsAdmin = async <T = Record<string, any>>(request: Request, draftContext?: any) => {
  return query<T>({ user: ADMIN_USER, request, draftContext });
};

/**
 * Execute a query as an AuthUser
 * @param user
 * @param request
 * @param draftContext
 */
export const queryAsAuthUser = async <T = Record<string, any>>(user: AuthUser, request: Request, draftContext?: any) => {
  return query<T>({ user, request, draftContext });
};

const queryAsTestUser = async <T = Record<string, any>>(testUser: UserTestData, request: Request, draftContext?: any) => {
  const user = await getAuthUser(testUser.id);
  return query<T>({ user, request, draftContext });
};

const query = async <T = Record<string, any>>(params: { user?: AuthUser; request: Request; draftContext?: any }) => {
  const execContext = executionContext('test', params.user, params.draftContext ?? undefined);
  execContext.changeDraftContext = (draftId) => {
    execContext.draft_context = draftId;
  };
  execContext.batch = computeLoaders(execContext, params.user);
  const { body } = await serverFromUser.executeOperation<T>(params.request, { contextValue: execContext });
  if (body.kind === 'single') {
    return body.singleResult;
  }
  return body.initialResult;
};

export const requestFileFromStorageAsAdmin = async (storageId: string) => {
  logApp.info(`[TEST] request on storage file ${storageId}`);
  const stream = await downloadFile(storageId);
  expect(stream, `No stream mean no file found in storage or error for ${storageId}`).not.toBeNull();
  return streamConverter(stream!);
};

export const readCsvFromFileStream = async (filePath: string, fileName: string) => {
  const file = fileToReadStream(filePath, fileName, fileName, 'text/csv');
  const rl = readline.createInterface({ input: file.createReadStream(), crlfDelay: Infinity });

  const csvLines: string[] = [];
  // Need an async interator to prevent blocking

  for await (const line of rl) {
    csvLines.push(line);
  }
  return csvLines;
};

export const createUploadFromTestDataFile = async (filePathRelativeFromData: string, fileName: string, mimetype: string, encoding?: string) => {
  const file = fs.createReadStream(
    new URL(`../data/${filePathRelativeFromData}`, import.meta.url),
  );
  const upload = new Upload();
  const fileUpload = {
    fieldName: 'fieldName',
    filename: fileName,
    mimetype,
    encoding: encoding || 'utf-8',
    createReadStream: () => file,
  };
  upload.promise = new Promise((executor) => {
    executor(fileUpload);
  });
  upload.file = fileUpload;
  return upload;
};

/**
 * Set the platform organisation.
 * @param organization organization to use as platform organisation.
 */
export const setOrganization = async (organization: OrganizationTestData) => {
  const platformOrganizationId = await getOrganizationIdByName(organization.name);
  const platformSettings: any = await getSettings(testContext);

  const input = [
    { key: 'platform_organization', value: [platformOrganizationId] },
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);

  expect(settingsResult.platform_organization).toBe(platformOrganizationId);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

/**
 * Remove any platform organization
 */
export const unSetOrganization = async () => {
  const platformSettings: any = await getSettings(testContext);
  const input = [
    { key: 'platform_organization', value: [] },
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);
  expect(settingsResult.platform_organization).toBeUndefined();
};

const AWAIT_MIN_INTERVAL = 200;
const AWAIT_MAX_INTERVAL = 2000;
const AWAIT_TARGET_POLLS = 20;

/**
 * Polling interval derived from the budget, so callers only have to express how long they
 * accept to wait. Aiming at AWAIT_TARGET_POLLS attempts keeps short budgets responsive and
 * long ones cheap, and the bounds avoid both a busy loop and a wait that overshoots the
 * budget on its first sleep.
 */
const intervalForBudget = (budgetMs: number) => {
  const target = Math.round(budgetMs / AWAIT_TARGET_POLLS);
  return Math.min(AWAIT_MAX_INTERVAL, Math.max(AWAIT_MIN_INTERVAL, target));
};

/** First stack frame outside this helper, so every measurement is attributable. */
const resolveCallSite = () => {
  const frames = new Error().stack?.split('\n').slice(1) ?? [];
  const frame = frames.find((f) => !f.includes('testQueryHelper'));
  return frame?.match(/([\w.-]+\.(?:ts|js):\d+:\d+)/)?.[1] ?? 'unknown';
};

interface AwaitUntilConditionOptions {
  /** Message added to the error when the budget is exhausted. */
  message?: string;
  /** Forces the polling interval in ms instead of deriving it from the budget. */
  intervalMs?: number;
  /** Expected result of the condition. */
  expectToBeTrue?: boolean;
}

/**
 * Waits until a condition holds, within a time budget.
 *
 * Every call reports how much of its budget it actually consumed, so the budgets can be set
 * from observed timings rather than from guesses.
 *
 * @param conditionPromise A function checking if the condition is verified.
 * @param budgetMs How long polling may go on, in ms. A poll is only started while the budget
 *                holds, so the budget bounds when polls start, not the total duration: a poll
 *                already in flight is never interrupted. Always stated by the caller: what a
 *                wait is allowed to cost is a decision of the test, never a default.
 * @param options Message, forced polling interval, expected result.
 */
export const awaitUntilCondition = async (
  conditionPromise: () => Promise<boolean>,
  budgetMs: number,
  options: AwaitUntilConditionOptions = {},
) => {
  const { message = '', expectToBeTrue = true } = options;
  const intervalMs = options.intervalMs ?? intervalForBudget(budgetMs);
  const callSite = resolveCallSite();
  const startTime = Date.now();

  let isConditionOk = await conditionPromise();
  let polls = 1;

  while (!isConditionOk === expectToBeTrue && Date.now() - startTime + intervalMs <= budgetMs) {
    await wait(intervalMs);
    isConditionOk = await conditionPromise();
    polls += 1;
  }

  const elapsed = Date.now() - startTime;
  const share = Math.round((elapsed / budgetMs) * 100);

  if (!isConditionOk === expectToBeTrue) {
    throw new Error(`Condition not met after ${elapsed}ms (budget ${budgetMs}ms, ${polls} polls) at ${callSite} - ${message}`);
  }

  logApp.info(`[TEST-AWAIT] ${callSite} met in ${elapsed}ms (${share}% of ${budgetMs}ms budget, ${polls} polls)`);
};

const serverFromUser = new ApolloServer<AuthContext>({
  schema: createSchema(),
  introspection: true,
  persistedQueries: false,
});
