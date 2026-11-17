import { Readable } from 'node:stream';
import { expect, it, describe, vi, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';
import { FINTEL_DESIGN_LOGO_MAX_SIZE, fintelDesignLogoStorageKey, readFintelDesignLogo } from '../../../src/modules/fintelDesign/fintelDesign-logo';

const LIST_QUERY = gql`
  query fintelDesigns(
    $first: Int
    $after: ID
    $orderBy: FintelDesignOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    fintelDesigns(
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
          default
          description
          file_id
          gradiantFromColor
          gradiantToColor
          textColor
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query fintelDesign($id: String!) {
    fintelDesign(id: $id) {
      id
      standard_id
      name
      description
      default
      file_id
      gradiantFromColor
      gradiantToColor
      textColor
    }
  }
`;

const CREATE_QUERY = gql`
  mutation fintelDesignAdd($input: FintelDesignAddInput!) {
    fintelDesignAdd(input: $input) {
      id
      name
      description
    }
  }
`;

const EDIT_QUERY = gql`
  mutation FintelDesignEdit($id: ID!, $input: [EditInput!], $file: Upload) {
    fintelDesignFieldPatch(id: $id, input: $input, file: $file) {
      id
      name
      description
      file_id
      textColor
      gradiantToColor
      gradiantFromColor
    }
  }
`;

const SET_DEFAULT_QUERY = gql`
  mutation fintelDesignSetDefault($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      default
    }
  }
`;

describe('Fintel Design resolver standard behavior', () => {
  let fintelDesignInternalId: string;
  const fintelDesignInput = {
    name: 'Test Fintel Design',
    description: 'A design for testing',
    default: false,
    gradiantFromColor: '#ffffff',
    gradiantToColor: '#000000',
    textColor: '#333333',
  };
  let secondFintelDesignInternalId: string;

  beforeAll(() => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  it('should create Fintel Design', async () => {
    // Create fintel design
    const fintelDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: fintelDesignInput },
    });
    expect(fintelDesign).not.toBeNull();
    expect(fintelDesign.data?.fintelDesignAdd).not.toBeNull();
    expect(fintelDesign.data?.fintelDesignAdd.name).toEqual('Test Fintel Design');
    fintelDesignInternalId = fintelDesign.data?.fintelDesignAdd.id;
  });

  it('should fintel design loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.fintelDesign).not.toBeNull();
    expect(queryResult.data?.fintelDesign.id).toEqual(fintelDesignInternalId);
    expect(queryResult.data?.fintelDesign.name).toEqual('Test Fintel Design');
  });

  it('should list Fintel Designs', async () => {
    const listResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(listResult.data?.fintelDesigns.edges.length).toBeGreaterThan(0);
  });

  it('should enforce unique default Fintel Design', async () => {
    await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelDesignInternalId,
        input: [{ key: 'default', value: [true] }],
      },
    });

    const secondDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          ...fintelDesignInput,
          name: 'Test Fintel Design 2',
          default: true,
        },
      },
    });
    secondFintelDesignInternalId = secondDesign.data?.fintelDesignAdd.id;

    const listResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 50 } });
    const firstDesign = listResult.data?.fintelDesigns.edges.find((e: { node: { id: string } }) => e.node.id === fintelDesignInternalId)?.node;
    const secondDesignFromList = listResult.data?.fintelDesigns.edges.find((e: { node: { id: string } }) => e.node.id === secondFintelDesignInternalId)?.node;
    expect(firstDesign?.default).toEqual(false);
    expect(secondDesignFromList?.default).toEqual(true);
  });

  it('should update Fintel Design', async () => {
    // update fintel design
    const updateResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelDesignInternalId,
        input: [{ key: 'name', value: ['Updated Fintel Design'] }],
      },
    });
    const fintelDesignName = updateResult.data?.fintelDesignFieldPatch.name;
    expect(fintelDesignName).toEqual('Updated Fintel Design');
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(queryResult.data?.fintelDesign.name).toEqual('Updated Fintel Design');
  });

  it('should delete FintelDesign', async () => {
    // delete fintel design
    const DELETE_QUERY = gql`
      mutation FintelDesignDelete($id: ID!) {
        fintelDesignDelete(id: $id)
      }
    `;
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: fintelDesignInternalId } });
    if (secondFintelDesignInternalId) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id: secondFintelDesignInternalId } });
    }
    const readAfterDelete = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(readAfterDelete).not.toBeNull();
    expect(readAfterDelete.data?.fintelDesign).toBeNull();
  });
});

describe('Fintel Design resolver default behavior', () => {
  let firstDesignId: string;
  let secondDesignId: string;

  beforeAll(() => {
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  it('should set fintel design as default', async () => {
    const firstDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Default test design 1',
          description: 'Default test design 1',
          default: false,
          gradiantFromColor: '#111111',
          gradiantToColor: '#222222',
          textColor: '#ffffff',
        },
      },
    });
    firstDesignId = firstDesign.data?.fintelDesignAdd.id;

    const setDefaultResult = await queryAsAdmin({
      query: SET_DEFAULT_QUERY,
      variables: {
        id: firstDesignId,
        input: [{ key: 'default', value: [true] }],
      },
    });

    expect(setDefaultResult.data?.fintelDesignFieldPatch.id).toEqual(firstDesignId);
    expect(setDefaultResult.data?.fintelDesignFieldPatch.default).toBe(true);

    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: firstDesignId } });
    expect(readResult.data?.fintelDesign.default).toBe(true);
  });

  it('should enforce uniqueness: setting a new default removes the previous one', async () => {
    const secondDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Default test design 2',
          description: 'Default test design 2',
          default: false,
          gradiantFromColor: '#333333',
          gradiantToColor: '#444444',
          textColor: '#ffffff',
        },
      },
    });
    secondDesignId = secondDesign.data?.fintelDesignAdd.id;

    await queryAsAdmin({
      query: SET_DEFAULT_QUERY,
      variables: {
        id: secondDesignId,
        input: [{ key: 'default', value: [true] }],
      },
    });

    const firstRead = await queryAsAdmin({ query: READ_QUERY, variables: { id: firstDesignId } });
    expect(firstRead.data?.fintelDesign.default).toBe(false);

    const secondRead = await queryAsAdmin({ query: READ_QUERY, variables: { id: secondDesignId } });
    expect(secondRead.data?.fintelDesign.default).toBe(true);
  });

  it('should cleanup default behavior test data', async () => {
    const DELETE_QUERY = gql`
      mutation FintelDesignDelete($id: ID!) {
        fintelDesignDelete(id: $id)
      }
    `;

    if (firstDesignId) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id: firstDesignId } });
    }

    if (secondDesignId) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id: secondDesignId } });
    }
  });
});

describe('Fintel Design resolver logo upload', () => {
  // A complete PNG of one pixel
  const PNG_LOGO = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
  const DELETE_QUERY = gql`
    mutation FintelDesignDelete($id: ID!) {
      fintelDesignDelete(id: $id)
    }
  `;
  let designId: string;

  // A file sent to the API as the browser sends it: named as an image, whatever its bytes
  const uploadOf = (content: Buffer, filename = 'logo.png') => {
    const file = { createReadStream: () => Readable.from([content]), filename, mimetype: 'image/png', encoding: '7bit' };
    const upload = new Upload();
    upload.promise = Promise.resolve(file);
    upload.file = file;
    return upload;
  };
  const sendLogo = (content: Buffer) => queryAsAdmin({ query: EDIT_QUERY, variables: { id: designId, file: uploadOf(content) } });
  const storedLogo = async () => {
    const { data } = await queryAsAdmin({ query: READ_QUERY, variables: { id: designId } });
    const design = data?.fintelDesign;
    return { fileId: design.file_id, content: await readFintelDesignLogo({ internal_id: designId, file_id: design.file_id, name: design.name }) };
  };

  beforeAll(async () => {
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    const created = await queryAsAdmin({ query: CREATE_QUERY, variables: { input: { name: 'Logo upload test design', default: false } } });
    designId = created.data?.fintelDesignAdd.id;
  });

  it('stores a valid logo under the design', async () => {
    const result = await sendLogo(PNG_LOGO);
    expect(result.errors).toBeUndefined();
    expect(result.data?.fintelDesignFieldPatch.file_id).toBe(fintelDesignLogoStorageKey(designId));
    expect((await storedLogo()).content).toEqual(PNG_LOGO);
  });

  it.each([
    ['bytes that are not an image, named as one', Buffer.from('<html><body>not a logo</body></html>'), 'The logo of the fintel design is not a supported image'],
    ['an image cut short', PNG_LOGO.subarray(0, PNG_LOGO.length - 12), 'The logo of the fintel design is not a supported image'],
    ['a logo over the limit', Buffer.concat([PNG_LOGO, Buffer.alloc(FINTEL_DESIGN_LOGO_MAX_SIZE)]), 'The logo of the fintel design is too large'],
  ])('refuses %s, and keeps the previous logo as it was', async (_case, content, message) => {
    const result = await sendLogo(content);
    expect(result.errors?.[0]?.message).toBe(message);
    expect(await storedLogo()).toEqual({ fileId: fintelDesignLogoStorageKey(designId), content: PNG_LOGO });
  });

  it('should cleanup logo upload test data', async () => {
    if (designId) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id: designId } });
    }
  });
});
