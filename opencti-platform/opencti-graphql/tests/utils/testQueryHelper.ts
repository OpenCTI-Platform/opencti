import { expect } from 'vitest';
import { print } from 'graphql/index';
import type { AxiosInstance } from 'axios';
import readline from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import Upload from 'graphql-upload/Upload.mjs';
import {
  ADMIN_USER,
  adminQuery,
  createUnauthenticatedClient,
  executeInternalQuery,
  getOrganizationIdByName,
  type OrganizationTestData,
  queryAsAdmin,
  testContext
} from './testQuery';
import { downloadFile } from '../../src/database/raw-file-storage';
import { streamConverter } from '../../src/database/file-storage';
import conf, { logApp } from '../../src/config/conf';
import { AUTH_REQUIRED, FORBIDDEN_ACCESS } from '../../src/config/errors';
import { getSettings, settingsEditField } from '../../src/domain/settings';
import { fileToReadStream } from '../../src/database/file-storage';
import { resetCacheForEntity } from '../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../src/schema/internalObject';

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
  if (requestResult.errors) {
    logApp.info('Unexpected error; requestResult:', { requestResult });
  }
  expect(requestResult.errors, `This errors should not be there: ${JSON.stringify(requestResult.errors)}`).toBeUndefined();
  return requestResult;
};

export const adminQueryWithSuccess = async (request: { query: any, variables: any }) => {
  const requestResult = await adminQuery({
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  if (requestResult.errors) {
    logApp.info('Unexpected error; requestResult:', { requestResult });
  }
  expect(requestResult.errors, `This errors should not be there: ${JSON.stringify(requestResult.errors)}`).toBeUndefined();
  return requestResult;
};

export const adminQueryWithError = async (
  request: { query: any, variables: any },
  errorMessage?: string,
  errorName?: string
) => {
  const requestResult = await adminQuery({
    query: request.query,
    variables: request.variables,
  });
  expect(requestResult, `Something is wrong with this query: ${request.query}`).toBeDefined();
  expect(requestResult.errors.length).toEqual(1);
  if (errorMessage) {
    expect(requestResult.errors[0].message, `error message: ${errorMessage} is expected, but got ${requestResult.errors[0].message}`).toBe(errorMessage);
  }
  if (errorName) {
    expect(requestResult.errors[0].extensions.code, `error is expected but got ${requestResult.errors[0].name}`).toBe(errorName);
  }
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
  if (requestResult.errors) {
    logApp.error('Unexpected error; request:', { request, requestResult });
  }
  expect(requestResult.errors, `This errors should not be there: ${JSON.stringify(requestResult.errors)}`).toBeUndefined();
  return requestResult;
};

/**
 * Execute the query as some User, and just return response (no validation).
 * @param client
 * @param request
 */
export const queryAsUser = async (client: AxiosInstance, request: { query: any, variables: any }) => {
  const result = await executeInternalQuery(client, print(request.query), request.variables);
  return result;
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
 * Execute the query as some User (see testQuery.ts), and verify that error is thrown.
 * @param client
 * @param request
 * @param errorMessage
 * @param errorName
 */
export const queryAsUserIsExpectedError = async (client: AxiosInstance, request: any, errorMessage?: string, errorName?: string) => {
  const queryResult = await executeInternalQuery(client, print(request.query), request.variables);
  logApp.info('queryAsUserIsExpectedError=> queryResult:', queryResult);
  expect(queryResult.errors, 'error is expected.').toBeDefined();
  expect(queryResult.errors?.length, `1 error is expected, but got ${queryResult.errors?.length} errors`).toBe(1);
  if (errorMessage) {
    expect(queryResult.errors[0].message, `error message: ${errorMessage} is expected, but got ${queryResult.errors[0].message}`).toBe(errorMessage);
  }
  if (errorName) {
    expect(queryResult.errors[0].extensions.code, `error is expected but got ${queryResult.errors[0].name}`).toBe(errorName);
  }
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
  return streamConverter(stream!);
};

export const readCsvFromFileStream = async (filePath: string, fileName: string) => {
  const file = fileToReadStream(filePath, fileName, fileName, 'text/csv');
  const rl = readline.createInterface({ input: file.createReadStream(), crlfDelay: Infinity });

  const csvLines: string[] = [];
  // Need an async interator to prevent blocking
  // eslint-disable-next-line no-restricted-syntax
  for await (const line of rl) {
    csvLines.push(line);
  }
  return csvLines;
};

/**
 * Enable Enterprise edition for test
 * @deprecated This function is useless: api-test are always run under EE with an env variable that take priority over settings
 */
export const enableEE = async () => {
  const platformSettings: any = await getSettings(testContext);
  const input = [
    { key: 'enterprise_license', value: [conf.get('app:enterprise_edition_license')] },
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);
  expect(settingsResult.platform_enterprise_edition.license_validated).toBeTruthy();
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

/**
 * Go back to community edition
 * @deprecated This function is useless: api-test are always run under EE with an env variable that take priority over settings
 */
export const disableEE = async () => {
  const platformSettings: any = await getSettings(testContext);
  const input = [
    { key: 'enterprise_license', value: [] },
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);
  // EE cant be disabled as setup by configuration
  expect(settingsResult.platform_enterprise_edition.license_validated).toBeTruthy();
};

export const createUploadFromTestDataFile = async (filePathRelativeFromData: string, fileName: string, mimetype: string, encoding?: string) => {
  const file = fs.createReadStream(
    path.resolve(__dirname, `../data/${filePathRelativeFromData}`),
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
 * Enable Enterprise edition and set the platform organisation.
 * @param organization organization to use as platform organisation.
 */
export const enableEEAndSetOrganization = async (organization: OrganizationTestData) => {
  const platformOrganizationId = await getOrganizationIdByName(organization.name);
  const platformSettings: any = await getSettings(testContext);

  await enableEE();

  const input = [
    { key: 'platform_organization', value: [platformOrganizationId] }
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);

  expect(settingsResult.platform_organization).toBe(platformOrganizationId);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

/**
 * Remove any platform organization and go back to community edition.
 */
export const enableCEAndUnSetOrganization = async () => {
  await disableEE();

  const platformSettings: any = await getSettings(testContext);
  const input = [
    { key: 'platform_organization', value: [] }
  ];
  const settingsResult = await settingsEditField(testContext, ADMIN_USER, platformSettings.id, input);
  expect(settingsResult.platform_organization).toBeUndefined();
};
