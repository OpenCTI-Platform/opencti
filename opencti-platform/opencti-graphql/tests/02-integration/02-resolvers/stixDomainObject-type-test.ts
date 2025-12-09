import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

interface EntityConfig {
  key: string;
  createMutation: string;
  deleteMutation: string;
  entityType: string;
  expectedTypeError: string;
  input: Record<string, any>;
}

interface TestEntities {
  [key: string]: string | null;
}

describe('STIX Domain Object Type Confusion Security Tests', () => {
  // Test entity IDs storage - only need report (used as wrong-type test entity for all endpoints)
  const testEntities: TestEntities = {
    report: null,
  };

  const entityConfig: EntityConfig[] = [
    // User-facing and case management entities
    { 
      key: 'report', 
      createMutation: 'reportAdd', 
      deleteMutation: 'reportEdit',
      entityType: 'Report',
      expectedTypeError: 'Report',
      input: { name: 'Test Report for Type Confusion', published: '2023-01-01T00:00:00.000Z' }
    },
    { 
      key: 'note', 
      createMutation: 'noteAdd', 
      deleteMutation: 'noteEdit',
      entityType: 'Note',
      expectedTypeError: 'Note',
      input: { content: 'Test Note for Type Confusion', objects: [] }
    },
    { 
      key: 'opinion', 
      createMutation: 'opinionAdd', 
      deleteMutation: 'opinionEdit',
      entityType: 'Opinion',
      expectedTypeError: 'Opinion',
      input: { opinion: 'strongly-agree', explanation: 'Test Opinion', objects: [] }
    },
    { 
      key: 'incident', 
      createMutation: 'incidentAdd', 
      deleteMutation: 'incidentEdit',
      entityType: 'Incident',
      expectedTypeError: 'Incident',
      input: { name: 'Test Incident for Type Confusion' }
    },
    { 
      key: 'caseIncident', 
      createMutation: 'caseIncidentAdd', 
      deleteMutation: 'caseIncidentDelete',
      entityType: 'Case-Incident',
      expectedTypeError: 'Case-Incident',
      input: { name: 'Test Case-Incident for Type Confusion' }
    },
    { 
      key: 'caseRfi', 
      createMutation: 'caseRfiAdd', 
      deleteMutation: 'caseRfiDelete',
      entityType: 'Case-Rfi',
      expectedTypeError: 'Case-Rfi',
      input: { name: 'Test Case-RFI for Type Confusion' }
    },
    { 
      key: 'caseRft', 
      createMutation: 'caseRftAdd', 
      deleteMutation: 'caseRftDelete',
      entityType: 'Case-Rft',
      expectedTypeError: 'Case-Rft',
      input: { name: 'Test Case-RFT for Type Confusion' }
    },
    { 
      key: 'feedback', 
      createMutation: 'feedbackAdd', 
      deleteMutation: 'feedbackDelete',
      entityType: 'Feedback',
      expectedTypeError: 'Feedback',
      input: { name: 'Test Feedback for Type Confusion' }
    },
    // Core threat intelligence entities
    { 
      key: 'malware', 
      createMutation: 'malwareAdd', 
      deleteMutation: 'malwareEdit',
      entityType: 'Malware',
      expectedTypeError: 'Malware',
      input: { name: 'Test Malware for Type Confusion' }
    },
    { 
      key: 'campaign', 
      createMutation: 'campaignAdd', 
      deleteMutation: 'campaignEdit',
      entityType: 'Campaign',
      expectedTypeError: 'Campaign',
      input: { name: 'Test Campaign for Type Confusion' }
    },
    { 
      key: 'threatActor', 
      createMutation: 'threatActorGroupAdd', 
      deleteMutation: 'threatActorGroupEdit',
      entityType: 'Threat-Actor-Group',
      expectedTypeError: 'Threat-Actor-Group',
      input: { name: 'Test Threat-Actor for Type Confusion' }
    },
    { 
      key: 'threatActorIndividual', 
      createMutation: 'threatActorIndividualAdd', 
      deleteMutation: 'threatActorIndividualDelete',
      entityType: 'Threat-Actor-Individual',
      expectedTypeError: 'Threat-Actor-Individual',
      input: { name: 'Test Threat-Actor-Individual for Type Confusion' }
    },
    { 
      key: 'intrusionSet', 
      createMutation: 'intrusionSetAdd', 
      deleteMutation: 'intrusionSetEdit',
      entityType: 'Intrusion-Set',
      expectedTypeError: 'Intrusion-Set',
      input: { name: 'Test Intrusion-Set for Type Confusion' }
    },
    { 
      key: 'attackPattern', 
      createMutation: 'attackPatternAdd', 
      deleteMutation: 'attackPatternEdit',
      entityType: 'Attack-Pattern',
      expectedTypeError: 'Attack-Pattern',
      input: { name: 'Test Attack-Pattern for Type Confusion' }
    },
    { 
      key: 'infrastructure', 
      createMutation: 'infrastructureAdd', 
      deleteMutation: 'infrastructureEdit',
      entityType: 'Infrastructure',
      expectedTypeError: 'Infrastructure',
      input: { name: 'Test Infrastructure for Type Confusion' }
    },
    { 
      key: 'tool', 
      createMutation: 'toolAdd', 
      deleteMutation: 'toolEdit',
      entityType: 'Tool',
      expectedTypeError: 'Tool',
      input: { name: 'Test Tool for Type Confusion' }
    },
    { 
      key: 'vulnerability', 
      createMutation: 'vulnerabilityAdd', 
      deleteMutation: 'vulnerabilityEdit',
      entityType: 'Vulnerability',
      expectedTypeError: 'Vulnerability',
      input: { name: 'Test Vulnerability for Type Confusion' }
    },
    { 
      key: 'courseOfAction', 
      createMutation: 'courseOfActionAdd', 
      deleteMutation: 'courseOfActionEdit',
      entityType: 'Course-Of-Action',
      expectedTypeError: 'Course-Of-Action',
      input: { name: 'Test Course-Of-Action for Type Confusion' }
    },
    { 
      key: 'indicator', 
      createMutation: 'indicatorAdd', 
      deleteMutation: 'indicatorDelete',
      entityType: 'Indicator',
      expectedTypeError: 'Indicator',
      input: { name: 'Test Indicator for Type Confusion', pattern: '[ipv4-addr:value = \'1.2.3.4\']', pattern_type: 'stix' }
    },
    { 
      key: 'malwareAnalysis', 
      createMutation: 'malwareAnalysisAdd', 
      deleteMutation: 'malwareAnalysisDelete',
      entityType: 'Malware-Analysis',
      expectedTypeError: 'Malware-Analysis',
      input: { product: 'Test Product', result_name: 'Test Malware-Analysis for Type Confusion' }
    },
    { 
      key: 'channel', 
      createMutation: 'channelAdd', 
      deleteMutation: 'channelDelete',
      entityType: 'Channel',
      expectedTypeError: 'Channel',
      input: { name: 'Test Channel for Type Confusion', channel_types: ['website'] }
    },
    { 
      key: 'narrative', 
      createMutation: 'narrativeAdd', 
      deleteMutation: 'narrativeDelete',
      entityType: 'Narrative',
      expectedTypeError: 'Narrative',
      input: { name: 'Test Narrative for Type Confusion' }
    },
    { 
      key: 'event', 
      createMutation: 'eventAdd', 
      deleteMutation: 'eventDelete',
      entityType: 'Event',
      expectedTypeError: 'Event',
      input: { name: 'Test Event for Type Confusion' }
    },
    // Supporting entities and reference data
    { 
      key: 'individual', 
      createMutation: 'individualAdd', 
      deleteMutation: 'individualEdit',
      entityType: 'Individual',
      expectedTypeError: 'Individual',
      input: { name: 'Test Individual for Type Confusion' }
    },
    { 
      key: 'sector', 
      createMutation: 'sectorAdd', 
      deleteMutation: 'sectorEdit',
      entityType: 'Sector',
      expectedTypeError: 'Sector',
      input: { name: 'Test Sector for Type Confusion' }
    },
    { 
      key: 'system', 
      createMutation: 'systemAdd', 
      deleteMutation: 'systemEdit',
      entityType: 'System',
      expectedTypeError: 'System',
      input: { name: 'Test System for Type Confusion' }
    },
    { 
      key: 'organization', 
      createMutation: 'organizationAdd', 
      deleteMutation: 'organizationDelete',
      entityType: 'Organization',
      expectedTypeError: 'Already deleted elements',
      input: { name: 'Test Organization for Type Confusion' }
    },
    { 
      key: 'country', 
      createMutation: 'countryAdd', 
      deleteMutation: 'countryEdit',
      entityType: 'Country',
      expectedTypeError: 'Country',
      input: { name: 'Test Country for Type Confusion' }
    },
    { 
      key: 'region', 
      createMutation: 'regionAdd', 
      deleteMutation: 'regionEdit',
      entityType: 'Region',
      expectedTypeError: 'Region',
      input: { name: 'Test Region for Type Confusion' }
    },
    { 
      key: 'city', 
      createMutation: 'cityAdd', 
      deleteMutation: 'cityEdit',
      entityType: 'City',
      expectedTypeError: 'City',
      input: { name: 'Test City for Type Confusion' }
    },
    { 
      key: 'position', 
      createMutation: 'positionAdd', 
      deleteMutation: 'positionEdit',
      entityType: 'Position',
      expectedTypeError: 'Position',
      input: { name: 'Test Position for Type Confusion', latitude: 48.8566, longitude: 2.3522 }
    },
    { 
      key: 'administrativeArea', 
      createMutation: 'administrativeAreaAdd', 
      deleteMutation: 'administrativeAreaDelete',
      entityType: 'Administrative-Area',
      expectedTypeError: 'Administrative-Area',
      input: { name: 'Test Administrative-Area for Type Confusion' }
    },
    { 
      key: 'grouping', 
      createMutation: 'groupingAdd', 
      deleteMutation: 'groupingDelete',
      entityType: 'Grouping',
      expectedTypeError: 'Grouping',
      input: { name: 'Test Grouping for Type Confusion', context: 'suspicious-activity' }
    },
    { 
      key: 'dataComponent', 
      createMutation: 'dataComponentAdd', 
      deleteMutation: 'dataComponentDelete',
      entityType: 'Data-Component',
      expectedTypeError: 'Data-Component',
      input: { name: 'Test Data-Component for Type Confusion' }
    },
    { 
      key: 'dataSource', 
      createMutation: 'dataSourceAdd', 
      deleteMutation: 'dataSourceDelete',
      entityType: 'Data-Source',
      expectedTypeError: 'Data-Source',
      input: { name: 'Test Data-Source for Type Confusion' }
    },
    { 
      key: 'language', 
      createMutation: 'languageAdd', 
      deleteMutation: 'languageDelete',
      entityType: 'Language',
      expectedTypeError: 'Language',
      input: { name: 'Test Language for Type Confusion' }
    },
  ];

  // Helper function to create test entity
  const createTestEntity = async (config: EntityConfig): Promise<string> => {
    const mutationName = config.createMutation.charAt(0).toUpperCase() + config.createMutation.slice(1);
    const createQuery = gql`
      mutation Create${mutationName}($input: ${mutationName}Input!) {
        ${config.createMutation}(input: $input) {
          id
        }
      }
    `;

    const result = await queryAsAdminWithSuccess({
      query: createQuery,
      variables: { input: config.input },
    });

    expect(result.data?.[config.createMutation]).not.toBeNull();
    expect(result.data?.[config.createMutation].id).toBeDefined();
    
    return result.data?.[config.createMutation].id;
  };

  // Helper function to delete test entity
  const deleteTestEntity = async (config: EntityConfig, entityId: string): Promise<void> => {
    // Check if this is a direct Delete mutation or Edit mutation pattern
    const isDirectDelete = config.deleteMutation.endsWith('Delete');
    
    let deleteQuery;
    if (isDirectDelete) {
      // Direct delete mutations (e.g., caseIncidentDelete)
      deleteQuery = gql`
        mutation Delete${config.deleteMutation}($id: ID!) {
          ${config.deleteMutation}(id: $id)
        }
      `;
    } else {
      // Edit mutations with nested delete (e.g., reportEdit)
      deleteQuery = gql`
        mutation Delete${config.deleteMutation}($id: ID!) {
          ${config.deleteMutation}(id: $id) {
            delete
          }
        }
      `;
    }

    await queryAsAdmin({
      query: deleteQuery,
      variables: { id: entityId },
    });
  };

  // Create only the report entity (used as wrong-type test entity for all endpoints)
  beforeAll(async () => {    
    const reportConfig = entityConfig[0]; // report is first in config
    testEntities.report = await createTestEntity(reportConfig);
  });

  // Clean up test entity after tests
  afterAll(async () => {    
    const reportConfig = entityConfig[0]; // report is first in config
    if (testEntities.report) {
      await deleteTestEntity(reportConfig, testEntities.report as string);
    }
  });

  // Generate test cases for each entity type (simplified approach)
  // Each endpoint is tested with ONE wrong entity type (report) + one positive test
  entityConfig.forEach((targetConfig) => {
    describe(`${targetConfig.entityType} deletion endpoint`, () => {
      // Skip report testing itself with report (would be same entity type)
      if (targetConfig.key !== 'report') {
        it(`should prevent deletion of Report via ${targetConfig.entityType} endpoint`, async () => {
          // Check if this is a direct Delete mutation or Edit mutation pattern
          const isDirectDelete = targetConfig.deleteMutation.endsWith('Delete');
          
          let deleteQuery;
          if (isDirectDelete) {
            // Direct delete mutations (e.g., caseIncidentDelete)
            deleteQuery = gql`
              mutation Delete($id: ID!) {
                ${targetConfig.deleteMutation}(id: $id)
              }
            `;
          } else {
            // Edit mutations with nested delete (e.g., reportEdit)
            deleteQuery = gql`
              mutation Delete($id: ID!) {
                ${targetConfig.deleteMutation}(id: $id) {
                  delete
                }
              }
            `;
          }

          // Execute query and manually validate error with flexible matching
          const result = await queryAsAdmin({
            query: deleteQuery,
            variables: { id: testEntities.report },
          });

          // Verify we got an error
          expect(result.errors).toBeDefined();
          expect(result.errors).toHaveLength(1);
          
          const error = result.errors![0];
          
          // Special case for Organization which uses AlreadyDeletedError
          if (targetConfig.key === 'organization') {
            expect(error.extensions?.code).toEqual('ALREADY_DELETED_ERROR');
            expect(error.message).toContain('Already deleted elements');
          } else {
            // For all other entities, verify FUNCTIONAL_ERROR code
            expect(error.extensions?.code).toEqual('FUNCTIONAL_ERROR');
            
            // Use flexible regex matching to accept both error message formats:
            // - "Cannot delete the object, entity of type {Type} not found."
            // - "Cannot delete the object, Stix-Domain-Object cannot be found."
            const errorPattern = /Cannot delete the object.*(?:not found|cannot be found)/;
            expect(error.message).toMatch(errorPattern);
          }
        });
      }

      it(`should successfully delete ${targetConfig.entityType} via its own endpoint`, async () => {
        // Create a temporary entity just for this positive test
        const tempEntityId = await createTestEntity(targetConfig);

        // Check if this is a direct Delete mutation or Edit mutation pattern
        const isDirectDelete = targetConfig.deleteMutation.endsWith('Delete');
        
        let deleteQuery;
        if (isDirectDelete) {
          // Direct delete mutations (e.g., caseIncidentDelete)
          deleteQuery = gql`
            mutation Delete($id: ID!) {
              ${targetConfig.deleteMutation}(id: $id)
            }
          `;
        } else {
          // Edit mutations with nested delete (e.g., reportEdit)
          deleteQuery = gql`
            mutation Delete($id: ID!) {
              ${targetConfig.deleteMutation}(id: $id) {
                delete
              }
            }
          `;
        }

        const result = await queryAsAdmin({
          query: deleteQuery,
          variables: { id: tempEntityId },
        });

        // Verify successful deletion
        if (isDirectDelete) {
          expect(result.data?.[targetConfig.deleteMutation]).toEqual(tempEntityId);
        } else {
          expect(result.data?.[targetConfig.deleteMutation].delete).toEqual(tempEntityId);
        }
        expect(result.errors).toBeUndefined();
      });
    });
  });
});
