import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { createUploadFromTestDataFile, queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER } from '../../../utils/testQuery';

describe('TAXII push ingestion resolver — configuration export / import', () => {
  let createdTaxiiPushId: string = '';

  it('should create a TAXII push ingester', async () => {
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation createTaxiiPushIngester($input: IngestionTaxiiCollectionAddInput!) {
          ingestionTaxiiCollectionAdd(input: $input) {
            id
            name
            description
            confidence_to_score
          }
        }
      `,
      variables: {
        input: {
          name: 'Taxii push for export test',
          description: 'Taxii push export description',
          confidence_to_score: true,
          user_id: ADMIN_USER.id,
          authorized_members: [],
        },
      },
    });
    const created = result.data?.ingestionTaxiiCollectionAdd;
    expect(created.id).toBeDefined();
    createdTaxiiPushId = created.id;
  });

  it('should generate correct export configuration', async () => {
    // Covers: taxiiCollectionExport (ingestion-taxii-collection-domain.ts)
    // Covers: IngestionTaxiiCollection.toConfigurationExport field resolver
    const result = await queryAsAdminWithSuccess({
      query: gql`
        query queryTaxiiPush($id: String!) {
          ingestionTaxiiCollection(id: $id) {
            name
            toConfigurationExport
          }
        }
      `,
      variables: { id: createdTaxiiPushId },
    });
    const exported = JSON.parse(result.data?.ingestionTaxiiCollection.toConfigurationExport);
    expect(exported.type).toBe('taxiiPushCollections');
    expect(exported.openCTI_version).toBeDefined();
    expect(exported.configuration).toMatchObject({
      name: 'Taxii push for export test',
      description: 'Taxii push export description',
      confidence_to_score: true,
    });
    // The portable subset only: user and authorized members stay platform-specific.
    expect(exported.configuration.user_id).toBeUndefined();
    expect(exported.configuration.authorized_members).toBeUndefined();
  });

  it('should parse an imported configuration file', async () => {
    // Covers: taxiiCollectionAddInputFromImport (ingestion-taxii-collection-domain.ts)
    const upload = await createUploadFromTestDataFile('taxiiPush/test-taxii-push.json', 'test-taxii-push.json', 'application/json');
    const result = await queryAsAdminWithSuccess({
      query: gql`
        query taxiiPushAddInputFromImport($file: Upload!) {
          ingestionTaxiiCollectionAddInputFromImport(file: $file) {
            name
            description
            confidence_to_score
          }
        }
      `,
      variables: { file: upload },
    });
    expect(result.data?.ingestionTaxiiCollectionAddInputFromImport).toMatchObject({
      name: 'taxiiPushAuto',
      description: 'Taxii push imported description',
      confidence_to_score: true,
    });
  });

  it('should refuse a configuration exported by an incompatible platform version', async () => {
    // Covers: the version guard of taxiiCollectionAddInputFromImport
    const upload = await createUploadFromTestDataFile('taxiiPush/test-taxii-push-outdated.json', 'test-taxii-push-outdated.json', 'application/json');
    const result = await queryAsAdmin({
      query: gql`
        query taxiiPushAddInputFromOutdatedImport($file: Upload!) {
          ingestionTaxiiCollectionAddInputFromImport(file: $file) {
            name
          }
        }
      `,
      variables: { file: upload },
    });
    expect(result.errors).toBeDefined();
    if (result.errors) {
      expect(result.errors[0].message).toContain('Invalid version of the platform');
    }
  });

  it('should delete the TAXII push ingester', async () => {
    const result = await queryAsAdminWithSuccess({
      query: gql`
        mutation deleteTaxiiPushIngester($id: ID!) {
          ingestionTaxiiCollectionDelete(id: $id)
        }
      `,
      variables: { id: createdTaxiiPushId },
    });
    expect(result.data?.ingestionTaxiiCollectionDelete).toEqual(createdTaxiiPushId);
  });
});
