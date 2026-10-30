import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { createUploadFromTestDataFile, queryAsAdminWithSuccess, queryUnauthenticatedIsExpectedForbidden } from '../../utils/testQueryHelper';

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
      theme_login_aside_color
      theme_login_aside_gradient_start
      theme_login_aside_gradient_end
      theme_login_aside_image
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
      theme_login_aside_color
      theme_login_aside_gradient_start
      theme_login_aside_gradient_end
      theme_login_aside_image
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
      theme_login_aside_color
      theme_login_aside_gradient_start
      theme_login_aside_gradient_end
      theme_login_aside_image
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
      theme_login_aside_color
      theme_login_aside_gradient_start
      theme_login_aside_gradient_end
      theme_login_aside_image
      built_in
    }
  }
`;

const EXPORT_THEME_QUERY = gql`
  query ThemeExport($id: ID!) {
    theme(id: $id) {
      name
      toConfigurationExport
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
      variables: { first: 10 },
    });

    const darkTheme = themes.data?.themes.edges.find(
      (edge: any) => edge.node.name === 'Filigran Dark',
    );
    darkThemeId = darkTheme?.node.id;

    const lightTheme = themes.data?.themes.edges.find(
      (edge: any) => edge.node.name === 'Filigran Light',
    );
    lightThemeId = lightTheme?.node.id;

    if (!darkThemeId || !lightThemeId) {
      throw new Error('Failed to initialize default themes for testing');
    }
  });

  it('should list default themes', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: { first: 10 },
    });

    expect(queryResult.data?.themes.edges.length).toBeGreaterThanOrEqual(2);

    const themeNames = queryResult.data?.themes.edges.map((edge: any) => edge.node.name);
    expect(themeNames).toContain('Filigran Dark');
    expect(themeNames).toContain('Filigran Light');
  });

  it('should not list themes when not authenticated', async () => {
    await queryUnauthenticatedIsExpectedForbidden({
      query: LIST_THEMES_QUERY,
      variables: { first: 10 },
    });
  });

  it('should read a specific theme', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: READ_THEME_QUERY,
      variables: { id: darkThemeId },
    });

    expect(queryResult.data?.theme).toBeDefined();
    expect(queryResult.data?.theme.name).toBe('Filigran Dark');
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
        theme_login_aside_gradient_start: '#050A14',
        theme_login_aside_gradient_end: '#0C1728',
      },
    };

    const theme = await queryAsAdmin({
      query: CREATE_THEME_MUTATION,
      variables: THEME_TO_CREATE,
    });

    customThemeId = theme.data?.themeAdd.id;

    expect(customThemeId).toBeDefined();
    expect(theme.data?.themeAdd.name).toBe('Custom Test Theme');
    expect(theme.data?.themeAdd.theme_background).toBe('#1a1a1a');
    expect(theme.data?.themeAdd.theme_primary).toBe('#ff6b6b');
    expect(theme.data?.themeAdd.built_in).toBe(false);
    expect(theme.data?.themeAdd.theme_login_aside_gradient_start).toBe('#050A14');
    expect(theme.data?.themeAdd.theme_login_aside_gradient_end).toBe('#0C1728');
  });

  it('should not create a theme with duplicate name', async () => {
    const DUPLICATE_THEME = {
      input: {
        name: 'Custom Test Theme',
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
      variables: DUPLICATE_THEME,
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
      variables: UPDATE_INPUT,
    });

    expect(updated.data?.themeFieldPatch.id).toBe(customThemeId);
    expect(updated.data?.themeFieldPatch.name).toBe('Updated Custom Theme');
    expect(updated.data?.themeFieldPatch.theme_primary).toBe('#00ff00');
  });

  it('should not update a theme name to a name already used by another theme', async () => {
    const UPDATE_INPUT = {
      id: customThemeId,
      input: [
        { key: 'name', value: 'Filigran Dark' },
      ],
    };

    const updated = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: UPDATE_INPUT,
    });

    expect(updated.errors).toBeDefined();
    expect(updated.errors?.[0].message).toContain('Theme name already exists');
  });

  it('should update a theme with its own unchanged name', async () => {
    const UPDATE_INPUT = {
      id: customThemeId,
      input: [
        { key: 'name', value: 'Updated Custom Theme' },
        { key: 'theme_primary', value: '#123456' },
      ],
    };

    const updated = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: UPDATE_INPUT,
    });

    expect(updated.data?.themeFieldPatch.name).toBe('Updated Custom Theme');
    expect(updated.data?.themeFieldPatch.theme_primary).toBe('#123456');
  });

  it('should update theme login aside to color', async () => {
    const UPDATE_INPUT = {
      id: customThemeId,
      input: [
        { key: 'theme_login_aside_color', value: '#ff0000' },
        { key: 'theme_login_aside_gradient_start', value: '' },
        { key: 'theme_login_aside_gradient_end', value: '' },
      ],
    };

    const updated = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: UPDATE_INPUT,
    });

    expect(updated.data?.themeFieldPatch.theme_login_aside_color).toBe('#ff0000');
    expect(updated.data?.themeFieldPatch.theme_login_aside_gradient_start).toBeFalsy();
    expect(updated.data?.themeFieldPatch.theme_login_aside_gradient_end).toBeFalsy();
  });

  it('should clear theme login aside fields', async () => {
    const UPDATE_INPUT = {
      id: customThemeId,
      input: [
        { key: 'theme_login_aside_color', value: '' },
      ],
    };

    const updated = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: UPDATE_INPUT,
    });

    expect(updated.data?.themeFieldPatch.theme_login_aside_color).toBeFalsy();
  });

  it('should search themes by name', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_THEMES_QUERY,
      variables: {
        search: 'Updated Custom',
        first: 10,
      },
    });

    expect(queryResult.data?.themes.edges.length).toBeGreaterThanOrEqual(1);
    expect(queryResult.data?.themes.edges[0].node.name).toContain('Updated Custom');
  });

  it('should not update a built-in theme', async () => {
    const updateResult = await queryAsAdmin({
      query: UPDATE_THEME_MUTATION,
      variables: {
        id: darkThemeId,
        input: [{ key: 'theme_primary', value: '#00ff00' }],
      },
    });

    expect(updateResult.errors).toBeDefined();
    expect(updateResult.errors?.[0].message).toContain('System default themes cannot be updated');
  });

  it('should not delete a built-in theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: darkThemeId },
    });

    expect(result.errors).toBeDefined();
    expect(result.errors?.[0].message).toContain('System default themes cannot be deleted');
  });

  it('should delete a custom theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: customThemeId },
    });

    expect(result.data?.themeDelete).toBe(customThemeId);

    const queryResult = await queryAsAdmin({
      query: READ_THEME_QUERY,
      variables: { id: customThemeId },
    });

    expect(queryResult.data?.theme).toBeNull();
  });

  it('should not delete a non-existent theme', async () => {
    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: 'non-existent-id' },
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
        },
      },
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
        orderMode: 'asc',
      },
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
      variables: { file: upload },
    });

    const importThemeId = theme.data?.themeImport.id;

    expect(importThemeId).toBeDefined();
    expect(theme.data?.themeImport.name).toBe('Test import theme');
    expect(theme.data?.themeImport.theme_background).toBe('#2bb6d3');
    expect(theme.data?.themeImport.theme_primary).toBe('#4c88a0');
    expect(theme.data?.themeImport.theme_logo).toBe('http://www.test.com/image.svg');
    expect(theme.data?.themeImport.built_in).toBe(false);

    const result = await queryAsAdmin({
      query: DELETE_THEME_MUTATION,
      variables: { id: importThemeId },
    });

    expect(result.data?.themeDelete).toBe(importThemeId);

    const queryResult = await queryAsAdmin({
      query: READ_THEME_QUERY,
      variables: { id: importThemeId },
    });

    expect(queryResult.data?.theme).toBeNull();
  });

  it('should import a theme file exported from the UI, with http(s) URLs and null login background fields', async () => {
    const FILE_NAME = 'test-theme-export.json';
    const upload = await createUploadFromTestDataFile(`theme/${FILE_NAME}`, FILE_NAME, 'application/json');
    const theme = await queryAsAdmin({ query: IMPORT_THEME_MUTATION, variables: { file: upload } });
    expect(theme.errors).toBeUndefined();
    const importedThemeId = theme.data?.themeImport.id;
    expect(theme.data?.themeImport.theme_logo).toBe('https://www.test.com/image.svg');
    expect(theme.data?.themeImport.theme_login_aside_image).toBe('http://www.test.com/aside.png');
    expect(theme.data?.themeImport.built_in).toBe(false);
    await queryAsAdmin({ query: DELETE_THEME_MUTATION, variables: { id: importedThemeId } });
  });

  it('should import a theme file with a logo that is a path of the platform, as the theme form accepts and exports it', async () => {
    const FILE_NAME = 'test-theme-relative-logo.json';
    const upload = await createUploadFromTestDataFile(`theme/${FILE_NAME}`, FILE_NAME, 'application/json');
    const theme = await queryAsAdmin({ query: IMPORT_THEME_MUTATION, variables: { file: upload } });
    expect(theme.errors).toBeUndefined();
    expect(theme.data?.themeImport.theme_logo).toBe('/static/image.svg');
    await queryAsAdmin({ query: DELETE_THEME_MUTATION, variables: { id: theme.data?.themeImport.id } });
  });

  it.each([
    ['a colour that is not hex', 'test-theme-rgb-color.json', 'theme_background'],
    ['an unknown key', 'test-theme-unknown-key.json', 'built_in'],
  ])('should refuse to import a theme file with %s', async (_, fileName, invalidKey) => {
    const upload = await createUploadFromTestDataFile(`theme/${fileName}`, fileName, 'application/json');
    const theme = await queryAsAdmin({ query: IMPORT_THEME_MUTATION, variables: { file: upload } });
    expect(theme.errors).toBeDefined();
    expect(theme.errors?.[0].message).toContain('Invalid theme file');
    expect(JSON.stringify(theme.errors)).toContain(invalidKey);
  });

  it('should export a theme as a file the import accepts, without its standard id', async () => {
    const input = {
      name: 'Theme to export',
      theme_background: '#1a1a1a',
      theme_paper: '#2a2a2a',
      theme_nav: '#1a1a1a',
      theme_primary: '#ff6b6b',
      theme_secondary: '#4ecdc4',
      theme_accent: '#45b7d1',
      theme_text_color: '#ffffff',
      theme_logo: 'https://example.com/logo.png',
    };
    const created = await queryAsAdminWithSuccess({ query: CREATE_THEME_MUTATION, variables: { input } });
    const themeId = created.data?.themeAdd.id;
    const exported = await queryAsAdminWithSuccess({ query: EXPORT_THEME_QUERY, variables: { id: themeId } });
    // The fields that are not set are left out, and the standard id is not part of a theme file
    expect(JSON.parse(exported.data?.theme.toConfigurationExport)).toEqual(input);
    await queryAsAdminWithSuccess({ query: DELETE_THEME_MUTATION, variables: { id: themeId } });
  });

  it('should export a built-in theme without its standard id', async () => {
    const exported = await queryAsAdminWithSuccess({ query: EXPORT_THEME_QUERY, variables: { id: darkThemeId } });
    const file = JSON.parse(exported.data?.theme.toConfigurationExport);
    expect(file.name).toBe('Filigran Dark');
    expect(file).not.toHaveProperty('standard_id');
    expect(file).not.toHaveProperty('built_in');
  });
});
