import { describe, expect, it } from 'vitest';
import { PLAYBOOK_COMPONENTS } from '../../../../../src/modules/playbook/playbook-components';
import { stixLoadById } from '../../../../../src/database/middleware';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import type { StixSighting } from '../../../../../src/types/stix-2-1-sro';
import { testExecutor } from './playbook-components-test-utils';

const PLAYBOOK_RULE_COMPONENT = PLAYBOOK_COMPONENTS.PLAYBOOK_RULE_COMPONENT;

describe('PLAYBOOK_RULE_COMPONENT', () => {
  describe('resolve_neighbors', () => {
    it('should resolve sighting_of and where_sighted of a sighting', async () => {
      const sighting = await stixLoadById(testContext, ADMIN_USER, 'sighting--ee20065d-2555-424f-ad9e-0f8428623c75') as StixSighting;
      expect(sighting).toBeDefined();
      const result = await PLAYBOOK_RULE_COMPONENT.executor(testExecutor({
        mainId: sighting.id,
        bundleObjects: [sighting],
        configuration: { rule: 'resolve_neighbors', inferences: false },
      }));

      expect(result.output_port).toEqual('out');
      const resultIds = result.bundle.objects.map((o) => o.id);
      expect(resultIds).toContain(sighting.sighting_of_ref);
      sighting.where_sighted_refs.forEach((whereSightedRef) => {
        expect(resultIds).toContain(whereSightedRef);
      });
    });
  });
});
