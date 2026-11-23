import { describe, expect, it } from 'vitest';
import { toRequirementOptions } from './PlaybookFlowFieldRequirementFilters';
import type { PlaybookFlowFieldRequirementFiltersQuery$data } from './__generated__/PlaybookFlowFieldRequirementFiltersQuery.graphql';

describe('playbook step "Listen intelligence requirement events": requirement selector', () => {
  it('offers each requirement by its name, its id as the value the step stores', () => {
    const data = {
      intelligenceRequirements: {
        edges: [
          { node: { id: 'ir-1', name: 'Ransomware on hospitals' } },
          null,
          { node: { id: 'ir-2', name: 'NGINX 1.27.1' } },
        ],
      },
    } as unknown as PlaybookFlowFieldRequirementFiltersQuery$data;
    expect(toRequirementOptions(data)).toEqual([
      { label: 'Ransomware on hospitals', value: 'ir-1' },
      { label: 'NGINX 1.27.1', value: 'ir-2' },
    ]);
  });

  it('offers nothing when the query answers nothing', () => {
    expect(toRequirementOptions(null)).toEqual([]);
    expect(toRequirementOptions({ intelligenceRequirements: null } as unknown as PlaybookFlowFieldRequirementFiltersQuery$data)).toEqual([]);
  });
});
