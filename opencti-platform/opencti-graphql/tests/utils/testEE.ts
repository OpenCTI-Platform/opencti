import { expect } from 'vitest';
import gql from 'graphql-tag';
import { adminQueryWithSuccess } from './testQueryHelper';
import { adminQuery } from './testQuery';

const PLATFORM_ORGANIZATION_QUERY = gql`
  mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        platform_organization {
          id
          name
        }
        enterprise_edition
        id
      }
    }
  }
`;

const getSettingsId = async () => {
  const SETTINGS_READ_QUERY = gql`
    query settings {
      settings {
        id
        platform_organization {
          id
          name
        }
      }
    }
  `;
  const queryResult = await adminQuery({ query: SETTINGS_READ_QUERY, variables: {} });
  return queryResult.data?.settings?.id;
};

export const activateEE = async () => {
  const settingsInternalId = await getSettingsId();
  const EEqueryResult = await adminQueryWithSuccess({
    query: PLATFORM_ORGANIZATION_QUERY,
    variables: {
      id: settingsInternalId,
      input: [
        { key: 'enterprise_edition', value: new Date().getTime() },
      ]
    }
  });
  expect(EEqueryResult?.data?.settingsEdit.fieldPatch.enterprise_edition).not.toBeUndefined();
};

export const deactivateEE = async () => {
  const settingsInternalId = getSettingsId();
  const EEDeactivationQuery = await adminQueryWithSuccess({
    query: PLATFORM_ORGANIZATION_QUERY,
    variables: {
      id: settingsInternalId,
      input: [{ key: 'enterprise_edition', value: [] }] },
  });
  expect(EEDeactivationQuery?.data?.settingsEdit.fieldPatch.enterprise_edition).toBeNull();
};
