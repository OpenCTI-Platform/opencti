import { testRenderHook } from '../../../../../utils/tests/test-render';
import { describe, expect, it } from 'vitest';
import { useStixRelationshipsMultiHorizontalBars } from './useStixRelationshipsMultiHorizontalBars';

describe('useStixRelationshipsMultiHorizontalBars', ()=>{
  const subSelectionMock = {
    perspective: 'relationships',
  };

  const finalFieldMock = 'internal_id';

  it('should return correct chartData when stixRelationshipsDistribution is filled with scos entities such as marking definitions', ()=> {
    const stixRelationshipsDistributionWithMarkings = [
      {
        label: '0810d778-0692-4afb-a967-7e1c574b1e92',
        value: 3,
        entity: {
          id: '0810d778-0692-4afb-a967-7e1c574b1e92',
          entity_type: 'Vulnerability',
          representative: { main: 'CVE-2013-0422' },
          stixCoreRelationshipsDistribution: [
            {
              label: '66045fab-f138-4fb3-ae4f-b28ad8a22761',
              value: 2,
              entity: {
                id: '66045fab-f138-4fb3-ae4f-b28ad8a22761',
                entity_type: 'Marking-Definition',
                representative: { main: 'TLP:CLEAR' },
                x_opencti_color: '#ffffff'
              }
            },
            {
              label: '42644a63-b184-46cd-b492-ec0bc23a1c17',
              value: 1,
              entity: {
                id: '42644a63-b184-46cd-b492-ec0bc23a1c17',
                entity_type: 'Marking-Definition',
                representative: { main: 'PAP:GREEN' },
                x_opencti_color: '#2e7d32'
              }
            }
          ]
        }
      },
      {
        label: '276322c9-6a6e-46e8-8333-6d9337cdddab',
        value: 2,
        entity: {
          id: '276322c9-6a6e-46e8-8333-6d9337cdddab',
          entity_type: 'Vulnerability',
          representative: { main: 'CVE-2012-0158' },
          stixCoreRelationshipsDistribution: [
            {
              label: '195e0fb3-86aa-4e94-909d-bee8b8518070',
              value: 1,
              entity: {
                id: '195e0fb3-86aa-4e94-909d-bee8b8518070',
                entity_type: 'Marking-Definition',
                representative: { main: 'PAP:RED' },
                x_opencti_color: '#c62828'
              }
            },
            {
              label: '42644a63-b184-46cd-b492-ec0bc23a1c17',
              value: 1,
              entity: {
                id: '42644a63-b184-46cd-b492-ec0bc23a1c17',
                entity_type: 'Marking-Definition',
                representative: { main: 'PAP:GREEN' },
                x_opencti_color: '#2e7d32'
              }
            }
          ]
        }
      },
      {
        label: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
        value: 2,
        entity: {
          id: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
          entity_type: 'Vulnerability',
          representative: { main: 'CVE-2010-3333' },
          stixCoreRelationshipsDistribution: [
            {
              label: '3c8e630f-b543-49ad-9209-33925493c930',
              value: 1,
              entity: {
                id: '3c8e630f-b543-49ad-9209-33925493c930',
                entity_type: 'Marking-Definition',
                representative: { main: 'PAP:AMBER' },
                x_opencti_color: '#d84315'
              }
            }
          ]
        }
      }
    ];

    const expectedchartData = [
      {
        name: 'TLP:CLEAR',
        data: [2, 0, 0]
      },
      {
        name: 'PAP:GREEN',
        data: [1, 1, 0]
      },
      {
        name: 'PAP:RED',
        data: [0, 1, 0]
      },
      {
        name: 'PAP:AMBER',
        data: [0, 0, 1]
      },
      {
        name: 'Others',
        data: [0, 0, 1]
      }
    ];

    const finalSubDistributionFieldMarkings = 'object-marking.internal_id';

    const { hook } = testRenderHook(() => {
      return useStixRelationshipsMultiHorizontalBars(subSelectionMock, stixRelationshipsDistributionWithMarkings,finalSubDistributionFieldMarkings,finalFieldMock);
    });

    const hookResult = hook.result.current;

    expect(hookResult.chartData).toEqual(expectedchartData);
  });

  it('should return correct chartData when stixRelationshipsDistribution is filled with non scos entities such as users', ()=> {
    const stixRelationshipsDistributionWithUsers = [
      {
        label: '0810d778-0692-4afb-a967-7e1c574b1e92',
        value: 2,
        entity: {
          id: '0810d778-0692-4afb-a967-7e1c574b1e92',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2013-0422'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: '88ec0c6a-13ce-5e39-B486-354fe4a7084f',
              value: 2,
              entity: {
                id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
                entity_type: 'User',
                name: 'admin'
              }
            }
          ]
        }
      },
      {
        label: '276322c9-6a6e-46e8-8333-6d9337cdddab',
        value: 2,
        entity: {
          id: '276322c9-6a6e-46e8-8333-6d9337cdddab',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2012-0158'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: '88ec0c6a-13ce-5e39-B486-354fe4a7084f',
              value: 2,
              entity: {
                id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
                entity_type: 'User',
                name: 'admin'
              }
            }
          ]
        }
      },
      {
        label: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
        value: 2,
        entity: {
          id: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2010-3333'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: '88ec0c6a-13ce-5e39-B486-354fe4a7084f',
              value: 2,
              entity: {
                id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
                entity_type: 'User',
                name: 'admin'
              }
            }
          ]
        }
      }
    ];

    const expectedchartData = [
      {
        name: 'admin',
        data: [2, 2, 2]
      }
    ];

    const finalSubDistributionFieldUsers = 'creator_id';

    const { hook } = testRenderHook(() => {
      return useStixRelationshipsMultiHorizontalBars(subSelectionMock, stixRelationshipsDistributionWithUsers,finalSubDistributionFieldUsers,finalFieldMock);
    });

    const hookResult = hook.result.current;

    expect(hookResult.chartData).toEqual(expectedchartData);
  });

  it('should return correct chartData when stixRelationshipsDistribution is filled with relationships', ()=> {
    const stixRelationshipsDistributionWithRelationships = [
      {
        label: '0810d778-0692-4afb-a967-7e1c574b1e92',
        value: 2,
        entity: {
          id: '0810d778-0692-4afb-a967-7e1c574b1e92',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2013-0422'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: 'Targets',
              value: 2,
              entity: null
            }
          ]
        }
      },
      {
        label: '276322c9-6a6e-46e8-8333-6d9337cdddab',
        value: 2,
        entity: {
          id: '276322c9-6a6e-46e8-8333-6d9337cdddab',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2012-0158'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: 'Targets',
              value: 2,
              entity: null
            }
          ]
        }
      },
      {
        label: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
        value: 3,
        entity: {
          id: '98256a7f-065f-4cf6-b1ee-14c846b8699f',
          entity_type: 'Vulnerability',
          representative: {
            main: 'CVE-2010-3333'
          },
          stixCoreRelationshipsDistribution: [
            {
              label: 'Targets',
              value: 3,
              entity: null
            }
          ]
        }
      }
    ];

    const expectedchartData = [
      {
        name: 'Targets',
        data: [2, 2, 3]
      }
    ];

    const finalSubDistributionFieldRelationships = 'relationship_type';

     const { hook } = testRenderHook(() => {
      return useStixRelationshipsMultiHorizontalBars(subSelectionMock, stixRelationshipsDistributionWithRelationships,finalSubDistributionFieldRelationships,finalFieldMock);
    });

    const hookResult = hook.result.current;

    expect(hookResult.chartData).toEqual(expectedchartData);
  });
});