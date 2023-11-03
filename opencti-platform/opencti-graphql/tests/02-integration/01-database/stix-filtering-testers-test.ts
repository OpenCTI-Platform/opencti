import { describe, expect, it } from 'vitest';

// basic set
import stixBundle from '../../data/DATA-TEST-STIX2_v2.json';

// specific data object that are not covered by the basic set
import stixReport from '../../data/stix2-report.json';
import stixIndicator from '../../data/stix2-indicator.json';
import stixIncident from '../../data/stix2-incident.json';

import * as testers from '../../../src/utils/stix-filtering/stix-testers';
import type { Filter } from '../../../src/utils/stix-filtering/filter-group';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';

describe('Filter testers', () => {
  const stixWithMarkings = stixBundle.objects.find((obj) => obj.object_marking_refs !== undefined);
  const stixWithoutMarkings = stixBundle.objects.find((obj) => obj.object_marking_refs === undefined);

  describe('Markings (key=markedBy)', () => {
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['markedBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27']
      };
      expect(testers.testMarkingFilter(stixWithMarkings, filter)).toEqual(true);
      expect(testers.testMarkingFilter(stixWithoutMarkings, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['markedBy'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27']
      };
      expect(testers.testMarkingFilter(stixWithMarkings, filter)).toEqual(false);
      expect(testers.testMarkingFilter(stixWithoutMarkings, filter)).toEqual(false);
    });
  });
  describe('Entity Type (key=entity_type)', () => {
    const report = stixBundle.objects.find((obj) => obj.type === 'report');

    // TODO: the test base does not contain entity whose type is stored in the extension, so we only test with a generated internal type
    it('should test positive for a stix object with matching filter, using generated internal type', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['Report', 'Note']
      };
      expect(testers.testEntityType(report, filter)).toEqual(true);
    });
    it('should test negative for a stix object with unmatching filter, using generated internal type', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Report', 'Note']
      };
      expect(testers.testEntityType(report, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter, using parent types', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Report']
      };
      expect(testers.testEntityType(report, filter)).toEqual(true);
    });
    it('should test negative for a stix object with unmatching filter, using parent types', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Stix-Object', 'Stix-Cyber-Observable', 'Report']
      };
      expect(testers.testEntityType(report, filter)).toEqual(false);
    });
  });

  describe('Indicator Types (key=indicator_types)', () => {
    // no indicator data in DATA-TEST-STIX2_v2.json, here is a local sample
    const stixWithIndicatorTypes = {
      id: 'indicator--0a68dbc1-d3bf-540c-bafa-8ab1697b2b41',
      spec_version: '2.1',
      revoked: false,
      confidence: 85,
      created: '2023-10-30T06:17:04.000Z',
      modified: '2023-11-01T00:22:47.352Z',
      pattern_type: 'stix',
      pattern: "[ipv4-addr:value = '138.201.189.141']",
      name: 'XWorm',
      description: 'XWorm',
      indicator_types: [
        'malicious-activity',
        'c2',
        'port:4444',
        'xworm'
      ],
      valid_from: '2023-10-30T06:17:03.000Z',
      valid_until: '2023-11-29T19:17:33.000Z',
      x_opencti_score: 50,
      x_opencti_detection: false,
      x_opencti_main_observable_type: 'Unknown',
      labels: [
        'c2',
        'xworm',
        'malicious-activity',
        'port:4444'
      ],
      x_opencti_id: '57bd0900-0ba3-48fe-b17c-0108f1c61442',
      x_opencti_type: 'Indicator',
      type: 'indicator',
      created_by_ref: 'identity--875ade1c-fc64-52f7-9299-092fd5aade9a'
    };

    const stixWithoutIndicatorTypes = stixBundle.objects[0];

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['indicator_types'],
        mode: 'AND',
        operator: 'eq',
        values: ['c2', 'port:4444']
      };
      expect(testers.testIndicator(stixWithIndicatorTypes, filter)).toEqual(true);
      expect(testers.testIndicator(stixWithoutIndicatorTypes, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['indicator_types'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testIndicator(stixWithIndicatorTypes, filter)).toEqual(false);
      expect(testers.testIndicator(stixWithoutIndicatorTypes, filter)).toEqual(false);
    });
  });

  describe('Workflow (key=x_opencti_workflow_id)', () => {
    const reportWithWorkflow = stixReport;
    const reportWithoutWorkflow = stixBundle.objects.find((obj) => obj.type === 'report');

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['x_opencti_workflow_id'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'bd156107-1f9a-43df-9595-574c467e9e21']
      };
      expect(testers.testWorkflow(reportWithWorkflow, filter)).toEqual(true);
      expect(testers.testWorkflow(reportWithoutWorkflow, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['createdBy'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testCreatedBy(reportWithWorkflow, filter)).toEqual(false);
      expect(testers.testCreatedBy(reportWithoutWorkflow, filter)).toEqual(false);
    });
  });

  describe('CreatedBy (key=createdBy)', () => {
    const stixWithCreatedBy = stixBundle.objects.find((obj) => obj.created_by_ref !== undefined);
    const stixWithoutCreatedBy = stixBundle.objects.find((obj) => obj.created_by_ref === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['createdBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'identity--7b82b010-b1c0-4dae-981f-7756374a17df']
      };
      expect(testers.testCreatedBy(stixWithCreatedBy, filter)).toEqual(true);
      expect(testers.testCreatedBy(stixWithoutCreatedBy, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['createdBy'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testCreatedBy(stixWithCreatedBy, filter)).toEqual(false);
      expect(testers.testCreatedBy(stixWithoutCreatedBy, filter)).toEqual(false);
    });
  });

  describe('Creator (key=creator)', () => {
    const stixWithCreator = stixBundle.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.creator_ids !== undefined);
    const stixWithoutCreator = stixBundle.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.creator_ids === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['creator'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', '88ec0c6a-13ce-5e39-b486-354fe4a7084f']
      };
      expect(testers.testCreator(stixWithCreator, filter)).toEqual(true);
      expect(testers.testCreator(stixWithoutCreator, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['creator'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testCreator(stixWithCreator, filter)).toEqual(false);
      expect(testers.testCreator(stixWithoutCreator, filter)).toEqual(false);
    });
  });

  describe('Assignee (key=assigneeTo)', () => {
    // no assignee data in DATA-TEST-STIX2_v2.json, here is a local sample
    const stixWithAssignee = {
      id: 'incident--a731f96e-4d1a-5333-81df-46c93e19abb8',
      spec_version: '2.1',
      type: 'incident',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'new-sdo',
          id: '84fdd243-adb4-4a9d-89c9-4e6593d9d7e4',
          type: 'Incident',
          created_at: '2023-10-27T12:48:23.246Z',
          updated_at: '2023-11-02T16:12:33.702Z',
          is_inferred: false,
          creator_ids: [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ],
          assignee_ids: [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ]
        }
      },
      created: '2023-10-27T12:48:23.216Z',
      modified: '2023-11-02T16:12:33.702Z',
      revoked: false,
      confidence: 70,
      lang: 'en',
      external_references: [
        {
          source_name: 'cve',
          external_id: 'CVE-2013-1347'
        }
      ],
      name: 'Incident with High severity',
      severity: 'high'
    };

    const stixWithoutAssignee = stixBundle.objects[0];

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['objectAssignee'],
        mode: 'AND',
        operator: 'eq',
        values: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f']
      };
      expect(testers.testAssignee(stixWithAssignee, filter)).toEqual(true);
      expect(testers.testIndicator(stixWithoutAssignee, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['indicator_types'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testIndicator(stixWithAssignee, filter)).toEqual(false);
      expect(testers.testIndicator(stixWithoutAssignee, filter)).toEqual(false);
    });
  });

  describe('Labels (key=labelledBy)', () => {
    const stixWithLabel = stixBundle.objects.find((obj) => obj.labels !== undefined);
    const stixWithoutLabel = stixBundle.objects.find((obj) => obj.labels === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['labelledBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'identity']
      };
      expect(testers.testLabel(stixWithLabel, filter)).toEqual(true);
      expect(testers.testLabel(stixWithoutLabel, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['labelledBy'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>', '<some-other-id>']
      };
      expect(testers.testLabel(stixWithLabel, filter)).toEqual(false);
      expect(testers.testLabel(stixWithoutLabel, filter)).toEqual(false);
    });
  });

  describe('Revoked (key=revoked)', () => {
    const stixWithRevoked = stixBundle.objects.find((obj) => obj.revoked !== undefined);
    const stixWithoutRevoked = stixBundle.objects.find((obj) => obj.revoked === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['revoked'],
        mode: 'OR',
        operator: 'eq',
        values: ['false']
      };
      expect(testers.testRevoked(stixWithRevoked, filter)).toEqual(true);
      expect(testers.testRevoked(stixWithoutRevoked, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['revoked'],
        mode: 'AND',
        operator: 'eq',
        values: ['true']
      };
      expect(testers.testRevoked(stixWithRevoked, filter)).toEqual(false);
      expect(testers.testRevoked(stixWithoutRevoked, filter)).toEqual(false);
    });
  });

  describe('Detection (key=x_opencti_detection)', () => {
    const stixWithDetection = stixIndicator;
    const stixWithoutDetection = stixBundle.objects[0];

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['x_opencti_detection'],
        mode: 'OR',
        operator: 'eq',
        values: ['true']
      };
      expect(testers.testDetection(stixWithDetection, filter)).toEqual(true);
      expect(testers.testDetection(stixWithoutDetection, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['x_opencti_detection'],
        mode: 'AND',
        operator: 'eq',
        values: ['false']
      };
      expect(testers.testDetection(stixWithDetection, filter)).toEqual(false);
      expect(testers.testDetection(stixWithoutDetection, filter)).toEqual(false);
    });
  });
  describe('Score (key=x_opencti_score)', () => {
    const stixWithScore = stixIndicator;
    const stixWithoutScore = stixBundle.objects[0];

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['x_opencti_score'],
        mode: 'OR',
        operator: 'lt',
        values: ['75']
      };
      expect(testers.testScore(stixWithScore, filter)).toEqual(true);
      expect(testers.testScore(stixWithoutScore, filter)).toEqual(false);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['x_opencti_score'],
        mode: 'AND',
        operator: 'lt',
        values: ['25']
      };
      expect(testers.testScore(stixWithScore, filter)).toEqual(false);
      expect(testers.testScore(stixWithoutScore, filter)).toEqual(false);
    });
  });

  describe('Confidence (key=confidence)', () => {
    const stixWithConfidence = stixBundle.objects.find((obj) => obj.confidence !== undefined);
    const stixWithoutConfidence = stixBundle.objects.find((obj) => obj.confidence === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['confidence'],
        mode: 'OR',
        operator: 'gt',
        values: ['50']
      };
      expect(testers.testConfidence(stixWithConfidence, filter)).toEqual(true);
      expect(testers.testConfidence(stixWithoutConfidence, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['confidence'],
        mode: 'AND',
        operator: 'lt',
        values: ['50']
      };
      expect(testers.testConfidence(stixWithConfidence, filter)).toEqual(false);
      expect(testers.testConfidence(stixWithoutConfidence, filter)).toEqual(false);
    });
  });

  describe('Pattern (key=pattern_type)', () => {
    const stixWithPattern = stixBundle.objects.find((obj) => obj.pattern_type !== undefined);
    const stixWithoutPattern = stixBundle.objects.find((obj) => obj.pattern_type === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['stix']
      };
      expect(testers.testPattern(stixWithPattern, filter)).toEqual(true);
      expect(testers.testPattern(stixWithoutPattern, filter)).toEqual(false);
      const filterCase: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['StiX'] // tester should be case insensitive
      };
      expect(testers.testPattern(stixWithPattern, filterCase)).toEqual(true);
      expect(testers.testPattern(stixWithoutPattern, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['pattern_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['not-stix']
      };
      expect(testers.testPattern(stixWithPattern, filter)).toEqual(false);
      expect(testers.testPattern(stixWithoutPattern, filter)).toEqual(false);
    });
  });

  // TODO: describe('Main Observable Type (key=x_opencti_main_observable_type)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
  // > should check that the test is case insensitive

  describe('Object contains (key=objectContains)', () => {
    const stixWithObjectRefs = stixBundle.objects.find((obj) => obj.object_refs !== undefined);
    const stixWithoutObjectRefs = stixBundle.objects.find((obj) => obj.object_refs === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c']
      };
      expect(testers.testObjectContains(stixWithObjectRefs, filter)).toEqual(true);
      expect(testers.testObjectContains(stixWithoutObjectRefs, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['objectContains'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>']
      };
      expect(testers.testObjectContains(stixWithObjectRefs, filter)).toEqual(false);
      expect(testers.testObjectContains(stixWithoutObjectRefs, filter)).toEqual(false);
    });
  });

  describe('Severity (key=severity)', () => {
    const stixWithSeverity = stixIncident;
    const stixWithoutSeverity = stixBundle.objects[0];

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['severity'],
        mode: 'OR',
        operator: 'eq',
        values: ['medium']
      };
      expect(testers.testSeverity(stixWithSeverity, filter)).toEqual(true);
      expect(testers.testSeverity(stixWithoutSeverity, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['severity'],
        mode: 'AND',
        operator: 'eq',
        values: ['low']
      };
      expect(testers.testSeverity(stixWithSeverity, filter)).toEqual(false);
      expect(testers.testSeverity(stixWithoutSeverity, filter)).toEqual(false);
    });
  });

  // TODO: describe('Priority (key=priority)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  describe('Relationship', () => {
    const stixRelationship = stixBundle.objects.find((obj) => obj.type === 'relationship');

    describe('Relation from (key=fromId)', () => {
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['fromId'],
          mode: 'OR',
          operator: 'eq',
          values: ['<some-id>', 'identity--360f3368-b911-4bb1-a7f9-0a8e4ef4e023']
        };
        expect(testers.testRelationFrom(stixRelationship, filter)).toEqual(true);
      });
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['fromId'],
          mode: 'AND',
          operator: 'eq',
          values: ['<some-id>']
        };
        expect(testers.testRelationFrom(stixRelationship, filter)).toEqual(false);
      });
    });

    describe('Relation to (key=toId)', () => {
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['toId'],
          mode: 'OR',
          operator: 'eq',
          values: ['<some-id>', 'identity--5556c4ab-3e5e-4d56-8410-60b29cecbeb6']
        };
        expect(testers.testRelationTo(stixRelationship, filter)).toEqual(true);
      });
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['toId'],
          mode: 'AND',
          operator: 'eq',
          values: ['<some-id>']
        };
        expect(testers.testRelationTo(stixRelationship, filter)).toEqual(false);
      });
    });

    // TODO: describe('From Types (key=fromTypes)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
    // TODO: describe('To Types (key=toTypes)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
  });

  describe('for Sighting', () => {
    const stixSighting = stixBundle.objects.find((obj) => obj.type === 'sighting');

    describe('Relation from (key=fromId)', () => {
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['fromId'],
          mode: 'OR',
          operator: 'eq',
          values: ['<some-id>', 'indicator--51640662-9c78-4402-932f-1d4531624723']
        };
        expect(testers.testRelationFrom(stixSighting, filter)).toEqual(true);
      });
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['fromId'],
          mode: 'AND',
          operator: 'eq',
          values: ['<some-id>']
        };
        expect(testers.testRelationFrom(stixSighting, filter)).toEqual(false);
      });
    });

    describe('Relation to (key=toId)', () => {
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['toId'],
          mode: 'OR',
          operator: 'eq',
          values: ['<some-id>', 'identity--72de07e8-e6ed-4dfe-b906-1e82fae1d132']
        };
        expect(testers.testRelationTo(stixSighting, filter)).toEqual(true);
      });
      it('should test positive for a stix object with matching filter', () => {
        const filter: Filter = {
          key: ['toId'],
          mode: 'AND',
          operator: 'eq',
          values: ['<some-id>']
        };
        expect(testers.testRelationTo(stixSighting, filter)).toEqual(false);
      });
    });

    // TODO: describe('From Types (key=fromTypes)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
    // TODO: describe('To Types (key=toTypes)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
  });

  describe('Instance (key=elementId)', () => {
    const stixWithExtId = stixBundle.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.id !== undefined);
    const stixRelationship = stixBundle.objects.find((obj) => obj.type === 'relationship');

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['elementId'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', '8bb3d3c5-ba1d-4434-82bb-23fe71d2b08b']
      };
      expect(testers.testInstanceType(stixWithExtId, filter)).toEqual(true);
    });
    it('should test positive for a stix object with matching filter + side event matching', () => {
      const filter: Filter = {
        key: ['elementId'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'identity--360f3368-b911-4bb1-a7f9-0a8e4ef4e023']
      };
      expect(testers.testInstanceType(stixRelationship, filter, true)).toEqual(true);
    });
    it('should test negative for a stix object with unmatching filter', () => {
      const filter: Filter = {
        key: ['elementId'],
        mode: 'AND',
        operator: 'eq',
        values: ['<some-id>']
      };
      expect(testers.testObjectContains(stixWithExtId, filter)).toEqual(false);
    });
  });
});
