import { afterEach, describe, expect, it, vi } from 'vitest';
import * as getFilterFromEntityTypeAndNodeType from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { useNodeAdversary, UseNodeAdversaryProps } from './useNodeAdversary';

import { DiamondEntityEnum } from '../diamondEnums';

describe('useNodeAdversary', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return correct values for a Threat Actor Group', () => {
    vi.spyOn(getFilterFromEntityTypeAndNodeType, 'default').mockReturnValue('Filter');
    const data: UseNodeAdversaryProps['data'] = {
      stixDomainObject: {
        entity_type: DiamondEntityEnum.threatActorGroup,
        aliases: ['Alias'],
        attributedFrom: {
          edges: [
            { node: { from: { name: 'Campaign test' } } },
          ],
        },
      },
      entityLink: '/dashboard/entities/threat-actor-group',
    };

    const result = useNodeAdversary({ data });
    expect(result.entityLink).toBe('/dashboard/entities/threat-actor-group');
    expect(result.isArsenal).toBe(false);
    expect(result.aliases).toBe('Alias');
    expect(result.generatedFilters).toBe('Filter');
    expect(result.lastAttributions).toBe('Campaign test');
  });

  it('should return correct values for an Arsenal type', () => {
    const data: UseNodeAdversaryProps['data'] = {
      stixDomainObject: {
        entity_type: DiamondEntityEnum.malware,
        aliases: ['Alias'],
        usedBy: {
          edges: [
            { node: { from: { name: 'Malware test' } } },
          ],
        },
      },
      entityLink: '/dashboard/entities/threat-actor-group',
    };

    const result = useNodeAdversary({ data });
    expect(result.isArsenal).toBe(true);
    expect(result.lastAttributions).toBe('Malware test');
  });

  it('should return correct values for other types', () => {
    const data: UseNodeAdversaryProps['data'] = {
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
      },
      entityLink: '/dashboard/entities/threat-actor-group',
    };
    const result = useNodeAdversary({ data });
    expect(result.isArsenal).toBe(false);
    expect(result.lastAttributions).toBe('Threat Actor test');
  });
});
