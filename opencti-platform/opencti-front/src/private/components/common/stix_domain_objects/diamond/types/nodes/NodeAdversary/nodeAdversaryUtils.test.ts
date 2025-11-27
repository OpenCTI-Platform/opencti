import { afterEach, describe, expect, it, vi } from 'vitest';
import * as getFilterFromEntityTypeAndNodeType from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { nodeAdversaryUtils, NodeAdversaryUtilsProps, StixDomainObjectFromDiamond } from './nodeAdversaryUtils';

import { DiamondEntityEnum } from '../diamondEnums';

describe('nodeAdversaryUtils', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return correct values for a Threat Actor Group', () => {
    vi.spyOn(getFilterFromEntityTypeAndNodeType, 'default').mockReturnValue('Filter');
    const data: NodeAdversaryUtilsProps['data'] = {
      stixDomainObject: {
        entity_type: DiamondEntityEnum.threatActorGroup,
        aliases: ['Alias'],
        attributedFrom: {
          edges: [
            { node: { from: { name: 'Campaign test' } } },
          ],
        },
      } as unknown as StixDomainObjectFromDiamond,
      entityLink: '/dashboard/entities/threat-actor-group',
    };

    const result = nodeAdversaryUtils({ data });
    expect(result.entityLink).toBe('/dashboard/entities/threat-actor-group');
    expect(result.isArsenal).toBe(false);
    expect(result.aliases).toBe('Alias');
    expect(result.generatedFilters).toBe('Filter');
    expect(result.lastAttributions).toBe('Campaign test');
  });

  it('should return correct values for an Arsenal type', () => {
    const data: NodeAdversaryUtilsProps['data'] = {
      stixDomainObject: {
        entity_type: DiamondEntityEnum.malware,
        aliases: ['Alias'],
        usedBy: {
          edges: [
            { node: { from: { name: 'Malware test' } } },
          ],
        },
      } as unknown as StixDomainObjectFromDiamond,
      entityLink: '/dashboard/entities/threat-actor-group',
    };

    const result = nodeAdversaryUtils({ data });
    expect(result.isArsenal).toBe(true);
    expect(result.lastAttributions).toBe('Malware test');
  });

  it('should return correct values for other types', () => {
    const data: NodeAdversaryUtilsProps['data'] = {
      stixDomainObject: {
        entity_type: DiamondEntityEnum.campaign,
        aliases: ['Alias'],
        usedBy: {
          edges: [
            { node: { from: { name: 'Malware test' } } },
          ],
        },
        attributedFrom: {
          edges: [
            { node: { from: { name: 'Campaign test' } } },
          ],
        },
        attributedTo: {
          edges: [
            { node: { to: { name: 'Threat Actor test' } } },
          ],
        },
      } as unknown as StixDomainObjectFromDiamond,
      entityLink: '/dashboard/entities/threat-actor-group',
    };
    const result = nodeAdversaryUtils({ data });
    expect(result.isArsenal).toBe(false);
    expect(result.lastAttributions).toBe('Threat Actor test');
  });
});
