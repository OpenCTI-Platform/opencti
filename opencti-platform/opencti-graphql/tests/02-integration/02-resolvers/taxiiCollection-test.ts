import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import type { TaxiiCollectionAddInput } from '../../../src/generated/graphql';
import { queryAsAdminWithSuccess, queryAsUser } from '../../utils/testQueryHelper';
import { logApp } from '../../../src/config/conf';
import { getGroupEntity } from '../../utils/domainQueryHelper';
import { AMBER_GROUP, USER_CONNECTOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { MEMBER_ACCESS_RIGHT_VIEW } from '../../../src/utils/access';

describe('Taxii collection resolver coverage', () => {
  let publicCollectionId: string;
  let amberRestrictedCollectionId: string;
  let restrictedCollectionId: string;

  it('Create new public taxii collection', async () => {
    const publicTaxiiInput: TaxiiCollectionAddInput = {
      name: 'Taxii collection for sharing public',
      description: 'Taxii collection for sharing public - description',
      authorized_members: [],
      taxii_public: true,
      include_inferences: true,
      score_to_confidence: false,
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Credential'], mode: 'or' }], filterGroups: [] })
    };

    const publicTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionAdd($input: TaxiiCollectionAddInput!) {
                    taxiiCollectionAdd(input: $input) {
                        id
                        name
                        taxii_public
                        filters
                        description
                        authorized_members {
                            id
                            name
                        }
                    }
                },
            `,
      variables: { input: publicTaxiiInput }
    });

    logApp.info('publicTaxiiResponse:', publicTaxiiResponse);
    expect(publicTaxiiResponse?.data?.taxiiCollectionAdd?.id).toBeDefined();
    publicCollectionId = publicTaxiiResponse?.data?.taxiiCollectionAdd?.id;

    expect(publicTaxiiResponse?.data?.taxiiCollectionAdd?.name).toBe('Taxii collection for sharing public');
    expect(publicTaxiiResponse?.data?.taxiiCollectionAdd?.description).toBe('Taxii collection for sharing public - description');
    expect(publicTaxiiResponse?.data?.taxiiCollectionAdd?.taxii_public).toBeTruthy();
    expect(publicTaxiiResponse?.data?.taxiiCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Credential'], mode: 'or' }], filterGroups: [] }));
  });

  it('Create restricted to group taxii collection', async () => {
    const amberGroup = await getGroupEntity(AMBER_GROUP);

    const amberRestrictedTaxiiInput: TaxiiCollectionAddInput = {
      name: 'Taxii collection for AMBER group',
      description: 'Taxii collection for AMBER group - description',
      taxii_public: false,
      include_inferences: true,
      score_to_confidence: false,
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Report'], mode: 'or' }], filterGroups: [] }),
      authorized_members: [{ id: amberGroup.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }]
    };

    const amberRestrictedTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionAdd($input: TaxiiCollectionAddInput!) {
                    taxiiCollectionAdd(input: $input) {
                        id
                        name
                        taxii_public
                        filters
                        description
                        authorized_members {
                            id
                            name
                        }
                    }
                },
            `,
      variables: { input: amberRestrictedTaxiiInput }
    });

    logApp.info('amberRestrictedTaxiiResponse:', amberRestrictedTaxiiResponse);
    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.id).toBeDefined();
    amberRestrictedCollectionId = amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.id;

    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.name).toBe('Taxii collection for AMBER group');
    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.description).toBe('Taxii collection for AMBER group - description');
    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.taxii_public).toBeFalsy();
    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.authorized_members.length).toBe(1);
    expect(amberRestrictedTaxiiResponse?.data?.taxiiCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Report'], mode: 'or' }], filterGroups: [] }));
  });

  it('Create no public but no restricted yet taxii collection', async () => {
    const restrictedTaxiiInput: TaxiiCollectionAddInput = {
      name: 'Taxii collection for internal usage',
      description: 'Taxii collection for internal usage - description',
      taxii_public: false,
      include_inferences: true,
      score_to_confidence: false,
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Campaign'], mode: 'or' }], filterGroups: [] })
    };

    const restrictedTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionAdd($input: TaxiiCollectionAddInput!) {
                    taxiiCollectionAdd(input: $input) {
                        id
                        name
                        taxii_public
                        filters
                        description
                        authorized_members {
                            id
                            name
                        }
                    }
                },
            `,
      variables: { input: restrictedTaxiiInput }
    });

    logApp.info('amberRestrictedTaxiiResponse:', restrictedTaxiiResponse);
    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.id).toBeDefined();
    restrictedCollectionId = restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.id;

    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.name).toBe('Taxii collection for internal usage');
    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.description).toBe('Taxii collection for internal usage - description');
    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.taxii_public).toBeFalsy();
    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.authorized_members.length).toBe(0);
    expect(restrictedTaxiiResponse?.data?.taxiiCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Campaign'], mode: 'or' }], filterGroups: [] }));
  });

  it('List all taxii with Admin', async () => {
    const allTaxiisResponse = await queryAsAdminWithSuccess({
      query: gql`
                query taxiiCollections {
                    taxiiCollections(search: "") {
                        edges {
                            node {
                                id
                                name
                                authorized_members {
                                    id
                                    name
                                }
                            }
                        }
                    }
                },
            `,
      variables: {}
    });

    logApp.info('allTaxiisResponse:', allTaxiisResponse);
    // Restricted taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for AMBER group').length).toBe(1);

    // Internal taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for internal usage').length).toBe(1);

    // Public taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for sharing public').length).toBe(1);
  });

  it('List all taxii with a user that has TAXIIAPI capacity', async () => {
    const allTaxiisResponse = await queryAsUser(USER_CONNECTOR.client, {
      query: gql`
                query taxiiCollections {
                    taxiiCollections(search: "") {
                        edges {
                            node {
                                id
                                name
                                authorized_members {
                                    id
                                    name
                                }
                            }
                        }
                    }
                },
            `,
      variables: {}
    });

    logApp.info('allTaxiisResponse:', allTaxiisResponse);
    // Restricted taxii should not be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for AMBER group').length).toBe(0);

    // Internal taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for internal usage').length).toBe(1);

    // Public taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for sharing public').length).toBe(1);
  });

  it('List all taxii with a user that has not TAXIIAPI capacity', async () => {
    const allTaxiisResponse = await queryAsUser(USER_PARTICIPATE.client, {
      query: gql`
                query taxiiCollections {
                    taxiiCollections(search: "") {
                        edges {
                            node {
                                id
                                name
                                authorized_members {
                                    id
                                    name
                                }
                            }
                        }
                    }
                },
            `,
      variables: {}
    });

    logApp.info('allTaxiisResponse:', allTaxiisResponse);
    // Restricted taxii should not be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for AMBER group').length).toBe(0);

    // Internal taxii should not be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Not public taxii with empty auth member for resolver tests').length).toBe(0);

    // Public taxii should be found
    expect(allTaxiisResponse?.data?.taxiiCollections?.edges
      .filter((taxii: any) => taxii.node.name === 'Taxii collection for sharing public').length).toBe(1);
  });

  it('Delete public taxii collection', async () => {
    const deletePublicTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionEdit($id: ID!) {
                    taxiiCollectionEdit(id: $id) {
                        delete
                    }
                },
            `,
      variables: { id: publicCollectionId }
    });
    logApp.info('deletePublicTaxiiResponse:', deletePublicTaxiiResponse);
    expect(deletePublicTaxiiResponse?.data?.taxiiCollectionEdit?.delete).toBeDefined();
  });

  it('Delete restricted to group taxii collection', async () => {
    const deleteGroupRestrictedTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionEdit($id: ID!) {
                    taxiiCollectionEdit(id: $id) {
                        delete
                    }
                },
            `,
      variables: { id: amberRestrictedCollectionId }
    });
    logApp.info('deleteGroupRestrictedTaxiiResponse:', deleteGroupRestrictedTaxiiResponse);
    expect(deleteGroupRestrictedTaxiiResponse?.data?.taxiiCollectionEdit?.delete).toBeDefined();
  });

  it('Delete not public taxii collection', async () => {
    const deleteRestrictedTaxiiResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation taxiiCollectionEdit($id: ID!) {
                    taxiiCollectionEdit(id: $id) {
                        delete
                    }
                },
            `,
      variables: { id: restrictedCollectionId }
    });
    logApp.info('deleteRestrictedTaxiiResponse:', deleteRestrictedTaxiiResponse);
    expect(deleteRestrictedTaxiiResponse?.data?.taxiiCollectionEdit?.delete).toBeDefined();
  });
});
