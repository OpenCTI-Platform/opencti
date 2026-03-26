import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const CREATE_QUERY = gql`
  mutation CustomViewAdd($input: CustomViewAddInput!) {
    customViewAdd(input: $input) {
      id
      name
      description
      target_entity_type
    }
  }
`;

const READ_QUERY = gql`
  query CustomViewDisplay($id: String!) {
    customViewDisplay(id: $id) {
      manifest
    }
  }
`;

const SETTINGS_QUERY = gql`
  query CustomViewsSettings($entityType: String!, $options: CustomViewsSettingsPaginationOptions) {
    customViewsSettings(entityType: $entityType, options: $options) {
      canEntityTypeHaveCustomViews
      customViews {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation CustomViewDelete($id: ID!) {
    customViewDelete(id: $id)
  }
`;

describe('CustomView resolver', () => {
  let customViewId: string;

  const CUSTOM_VIEW_TO_CREATE = {
    input: {
      name: 'Test Custom View',
      description: 'My custom view',
      target_entity_type: 'Report',
      manifest: '{}',
    },
  };

  it('should create a custom view', async () => {
    const result = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CUSTOM_VIEW_TO_CREATE,
    });

    expect(result).not.toBeNull();
    expect(result.data?.customViewAdd).not.toBeNull();
    expect(result.data?.customViewAdd.name).toEqual('Test Custom View');

    customViewId = result.data?.customViewAdd.id;
  });

  it('should read custom view display', async () => {
    const result = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: customViewId },
    });

    expect(result).not.toBeNull();
    expect(result.data?.customViewDisplay).not.toBeNull();
  });

  it('should get settings without options', async () => {
    const result = await queryAsAdmin({
      query: SETTINGS_QUERY,
      variables: { entityType: 'Report' },
    });

    expect(result).not.toBeNull();
    expect(result.data?.customViewsSettings).not.toBeNull();
  });

  it('should get settings with options', async () => {
    const result = await queryAsAdmin({
      query: SETTINGS_QUERY,
      variables: {
        entityType: 'Report',
        options: { first: 5 },
      },
    });

    expect(result).not.toBeNull();
    expect(result.data?.customViewsSettings).not.toBeNull();
  });

  it('should delete custom view', async () => {
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: customViewId },
    });

    const result = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: customViewId },
    });

    expect(result.data?.customViewDisplay).toBeNull();
  });
});
