import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { createUploadFromTestDataFile, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const CREATE_THEME_MUTATION = gql`
  mutation ThemeAdd($input: ThemeAddInput!) {
    themeAdd(input: $input) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login
      built_in
    }
  }
`;

const UPDATE_THEME_MUTATION = gql`
  mutation ThemeFieldPatch($id: ID!, $input: [EditInput!]!) {
    themeFieldPatch(id: $id, input: $input) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
    }
  }
`;

const DELETE_THEME_MUTATION = gql`
  mutation ThemeDelete($id: ID!) {
    themeDelete(id: $id)
  }
`;

const READ_THEME_QUERY = gql`
  query Theme($id: ID!) {
    theme(id: $id) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login
      built_in
    }
  }
`;

const LIST_THEMES_QUERY = gql`
  query Themes(
    $first: Int
    $after: ID
    $orderBy: ThemeOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    themes(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          theme_background
          theme_paper
          theme_nav
          theme_primary
          theme_secondary
          theme_accent
          theme_text_color
          built_in
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const IMPORT_THEME_MUTATION = gql`
  mutation ThemeImport($file: Upload!) {
    themeImport(file: $file) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login
      built_in
    }
  }
`;

describe('Themes resolver testing', () => {
  let customThemeId = '';
  let darkThemeId = '';
  let lightThemeId = '';

  beforeAll(async () => {
    const themes = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: { first: 10 }
    });

    const darkTheme = themes.data?.themes.edges.find(
      (edge: any) => edge.node.name === 'Dark'
    );
    darkThemeId = darkTheme?.node.id;

    const lightTheme = themes.data?.themes.edges.find(
      (edge: any) => edge.node.name === 'Light'
    );
    lightThemeId = lightTheme?.node.id;

    if (!darkThemeId || !lightThemeId) {
      throw new Error('Failed to initialize default themes for testing');
    }
  });

  it('should list default themes', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: { first: 10 }
    });

    expect(queryResult.data?.themes.edges.length).toBeGreaterThanOrEqual(2);

    const themeNames = queryResult.data?.themes.edges.map((edge: any) => edge.node.name);
    expect(themeNames).toContain('Dark');
    expect(themeNames).toContain('Light');
  });

  it('should read a specific theme', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: READ_THEME_QUERY,
      variables: { id: darkThemeId }
    });

    expect(queryResult.data?.theme).toBeDefined();
    expect(queryResult.data?.theme.name).toBe('Dark');
    expect(queryResult.data?.theme.built_in).toBe(true);
    expect(queryResult.data?.theme.theme_background).toBeDefined();
    expect(queryResult.data?.theme.theme_primary).toBeDefined();
  });

  it('should create a custom theme', async () => {
    const THEME_TO_CREATE = {
      input: {
        name: 'Custom Test Theme',
        theme_background: '#1a1a1a',
        theme_paper: '#2a2a2a',
        theme_nav: '#1a1a1a',
        theme_primary: '#ff6b6b',
        theme_secondary: '#4ecdc4',
        theme_accent: '#45b7d1',
        theme_text_color: '#ffffff',
        theme_logo: 'https://example.com/logo.png',
        theme_logo_collapsed: 'https://example.com/logo-small.png',
        theme_logo_login: 'https://example.com/logo-login.png',
      },
    };

    const theme = await queryAsAdmin({
      query: CREATE_THEME_MUTATION,
      variables: THEME_TO_CREATE
    });

    customThemeId = theme.data?.themeAdd.id;

    expect(customThemeId).toBeDefined();
    expect(theme.data?.themeAdd.name).toBe('Custom Test Theme');
    expect(theme.data?.themeAdd.theme_background).toBe('#1a1a1a');
    expect(theme.data?.themeAdd.theme_primary).toBe('#ff6b6b');
    expect(theme.data?.themeAdd.built_in).toBe(false);
  });

  it('should not create a theme with duplicate name', async () => {
    const DUPLICATE_THEME = {
      input: {
        name: 'Custom Test Theme', // Same name as above
        theme_background: '#000000',
        theme_paper: '#111111',
        theme_nav: '#000000',
        theme_primary: '#0000ff',
        theme_secondary: '#00ff00',
        theme_accent: '#ff0000',
        theme_text_color: '#ffffff',
      },
    };

    const result = await queryAsAdmin({
      query: CREATE_THEME_MUTATION,
      variables: DUPLICATE_THEME
    });

    expect(result.errors).toBeDefined();
    expect(result.errors?.[0].message).toContain('Theme name already exists');
  });

  it('should update a theme', async () => {
    const UPDATE_INPUT = {
      id: customThemeId,
      input: [
        { key: 'theme_primary', value: '#00ff00' },
        { key: 'name', value: 'Updated Custom Theme' },
      ],
    };

    const updated = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: UPDATE_INPUT
    });

    expect(updated.data?.themeFieldPatch.id).toBe(customThemeId);
    expect(updated.data?.themeFieldPatch.name).toBe('Updated Custom Theme');
    expect(updated.data?.themeFieldPatch.theme_primary).toBe('#00ff00');
  });

  it('should search themes by name', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: {
        search: 'Updated Custom',
        first: 10
      }
    });

    expect(queryResult.data?.themes.edges.length).toBeGreaterThanOrEqual(1);
    expect(queryResult.data?.themes.edges[0].node.name).toContain('Updated Custom');
  });

  it('should not delete a built-in theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: darkThemeId }
    });

    expect(result.errors).toBeDefined();
    expect(result.errors?.[0].message).toContain('System default themes cannot be deleted');
  });

  it('should delete a custom theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: customThemeId }
    });

    expect(result.data?.themeDelete).toBe(customThemeId);

    const queryResult = await queryAsAdmin({
      query: READ_THEME_QUERY,
      variables: { id: customThemeId }
    });

    expect(queryResult.data?.theme).toBeNull();
  });

  it('should not delete a non-existent theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: 'non-existent-id' }
    });

    expect(result.errors).toBeDefined();
    expect(result.errors?.[0].message).toContain('cannot be found');
  });

  it('should filter themes by built_in status', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [{
            key: 'built_in',
            values: ['true'],
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        }
      }
    });

    expect(queryResult.data?.themes.edges.length).toBeGreaterThanOrEqual(2);
    queryResult.data?.themes.edges.forEach((edge: any) => {
      expect(edge.node.built_in).toBe(true);
    });
  });

  it('should order themes by name', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: {
        first: 10,
        orderBy: 'name',
        orderMode: 'asc'
      }
    });

    const names = queryResult.data?.themes.edges.map((edge: any) => edge.node.name);
    const sortedNames = [...names].sort();
    expect(names).toEqual(sortedNames);
  });

  it('should import a theme json file', async () => {
    const FILE_NAME = 'test-theme.json';
    const upload = await createUploadFromTestDataFile(`theme/${FILE_NAME}`, FILE_NAME, 'application/json');

    const theme = await queryAsAdmin({
      query: IMPORT_THEME_MUTATION,
      variables: {
        file: upload
      }
    });

    const importThemeId = theme.data?.themeImport.id;

    expect(importThemeId).toBeDefined();
    expect(theme.data?.themeImport.name).toBe('Test import theme');
    expect(theme.data?.themeImport.theme_background).toBe('#2bb6d3');
    expect(theme.data?.themeImport.theme_primary).toBe('#4c88a0');
    expect(theme.data?.themeImport.theme_logo).toBe('http://www.test.com/image.svg');
    expect(theme.data?.themeImport.built_in).toBe(false);

    // delete the imported theme
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: importThemeId }
    });

    expect(result.data?.themeDelete).toBe(importThemeId);

    const queryResult = await queryAsAdmin({
      query: READ_THEME_QUERY,
      variables: { id: importThemeId }
    });

    expect(queryResult.data?.theme).toBeNull();
  });
});
