import { expect } from 'vitest';
import { print } from 'graphql/index';
import type { AxiosInstance } from 'axios';
import { createUnauthenticatedClient, executeInternalQuery, queryAsAdmin } from './testQuery';
import { downloadFile, streamConverter } from '../../src/database/file-storage';
import { logApp } from '../../src/config/conf';
import { AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../../src/config/errors';

// Helper for test usage whit expect inside.
// vitest cannot be an import of testQuery, so it must be a separate file.

/**
 * Test utility.
 * Execute the query and verify that there is no error before returning result.
 * @param request
 */
export const queryAsAdminWithSuccess = async (request: { query: any, variables: any }) => {
  const requestResult = await queryAsAdmin({
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  expect(requestResult.errors, `This errors should not be there: ${requestResult.errors}`).toBeUndefined();
  return requestResult;
};

/**
 * Execute the query as some User, and verify success and return query result.
 * @param client
 * @param request
 */
export const queryAsUserWithSuccess = async (client: AxiosInstance, request: { query: any, variables: any }) => {
  const requestResult = await executeInternalQuery(client, print(request.query), request.variables);
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  expect(requestResult.errors, `This errors should not be there: ${requestResult.errors}`).toBeUndefined();
  return requestResult;
};

/**
 * Execute the query as some User (see testQuery.ts), and verify that access is forbidden.
 * @param client
 * @param request
 */
export const queryAsUserIsExpectedForbidden = async (client: AxiosInstance, request: any, message?: string) => {
  const queryResult = await executeInternalQuery(client, print(request.query), request.variables);
  logApp.info('queryAsUserIsExpectedForbidden=> queryResult:', queryResult);
  expect(queryResult.errors, 'FORBIDDEN_ACCESS is expected.').toBeDefined();
  expect(queryResult.errors?.length, message ?? `FORBIDDEN_ACCESS is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  expect(queryResult.errors[0].extensions.code, `FORBIDDEN_ACCESS is expected but got ${queryResult.errors[0].name}`).toBe(FORBIDDEN_ACCESS);
};

/**
 * Call a graphQL request with no authentication / no login and verify that access is forbidden.
 * @param request
 */
export const queryUnauthenticatedIsExpectedForbidden = async (request: any) => {
  const anonymous = createUnauthenticatedClient();

  const queryResult = await executeInternalQuery(anonymous, print(request.query), request.variables);
  expect(queryResult.errors, 'AUTH_REQUIRED error is expected but got zero errors.').toBeDefined();
  expect(queryResult.errors?.length, `AUTH_REQUIRED is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  expect(queryResult.errors[0].extensions.code, `AUTH_REQUIRED is expected but got ${queryResult.errors[0].name}`).toBe(AUTH_REQUIRED);
};

export const requestFileFromStorageAsAdmin = async (storageId: string) => {
  logApp.info(`[TEST] request on storage file ${storageId}`);
  const stream = await downloadFile(storageId);
  expect(stream, `No stream mean no file found in storage or error for ${storageId}`).not.toBeNull();
  return streamConverter(stream);
};
