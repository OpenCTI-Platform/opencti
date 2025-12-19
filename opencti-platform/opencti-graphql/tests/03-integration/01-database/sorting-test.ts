import { describe, expect, it, vi } from 'vitest';
import { buildElasticSortingForAttributeCriteria } from '../../../src/utils/sorting';
import { SYSTEM_USER } from '../../../src/utils/access';
import { testContext } from '../../utils/testQuery';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

describe('Sorting utilities', () => {
  // Activate EE for this test
  vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
  vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  let sorting;
  it('buildElasticSortingForAttributeCriteria throws on error if pir sorting and user has not the rights', async () => {
    sorting = async () => buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'pir_score', 'asc', 'fakePirId');
    await expect(sorting).rejects.toThrowError('No PIR found');
  });
});
