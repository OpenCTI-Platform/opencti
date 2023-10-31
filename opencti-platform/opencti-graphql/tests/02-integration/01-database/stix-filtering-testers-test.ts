import { describe, expect, it } from 'vitest';

import data from '../../data/DATA-TEST-STIX2_v2.json';
import * as testers from '../../../src/utils/stix-filtering/stix-testers';
import type { Filter } from '../../../src/utils/stix-filtering/filter-group';
import { STIX_EXT_OCTI } from '../../../src/types/stix-extensions';

describe('Filter testers', () => {
  const stixWithMarkings = data.objects.find((obj) => obj.object_marking_refs !== undefined);
  const stixWithoutMarkings = data.objects.find((obj) => obj.object_marking_refs === undefined);

  describe('Markings (key=markedBy)', () => {
    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['markedBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27']
      };
      expect(testers.testMarkingFilter(stixWithMarkings, filter)).toEqual(true);
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
    const stixReport = data.objects.find((obj) => obj.type === 'report');

    // TODO: the test base does not contain entity whose type is stored in the extension, so we only test with a generated internal type
    it('should test positive for a stix object with matching filter, using generated internal type', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['Report', 'Note']
      };
      expect(testers.testEntityType(stixReport, filter)).toEqual(true);
    });
    it('should test negative for a stix object with unmatching filter, using generated internal type', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Report', 'Note']
      };
      expect(testers.testEntityType(stixReport, filter)).toEqual(false);
    });
    it('should test positive for a stix object with matching filter, using parent types', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Report']
      };
      expect(testers.testEntityType(stixReport, filter)).toEqual(true);
    });
    it('should test negative for a stix object with unmatching filter, using parent types', () => {
      const filter: Filter = {
        key: ['entity_type'],
        mode: 'AND',
        operator: 'eq',
        values: ['Stix-Object', 'Stix-Cyber-Observable', 'Report']
      };
      expect(testers.testEntityType(stixReport, filter)).toEqual(false);
    });
  });

  // TODO: describe('Indicator Types (key=indicator_types)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
  // > should check that the test is case insensitive
  // TODO: describe('Workflow (key=x_opencti_workflow_id)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  describe('CreatedBy (key=createdBy)', () => {
    const stixWithCreatedBy = data.objects.find((obj) => obj.created_by_ref !== undefined);
    const stixWithoutCreatedBy = data.objects.find((obj) => obj.created_by_ref === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['createdBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'identity--7b82b010-b1c0-4dae-981f-7756374a17df']
      };
      expect(testers.testCreatedBy(stixWithCreatedBy, filter)).toEqual(true);
    });
    it('should test positive for a stix object with matching filter', () => {
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
    const stixWithCreator = data.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.creator_ids !== undefined);
    const stixWithoutCreator = data.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.creator_ids === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['creator'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', '88ec0c6a-13ce-5e39-b486-354fe4a7084f']
      };
      expect(testers.testCreator(stixWithCreator, filter)).toEqual(true);
    });
    it('should test positive for a stix object with matching filter', () => {
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

  // TODO: describe('Assignee (key=assigneeTo)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  describe('Labels (key=labelledBy)', () => {
    const stixWithLabel = data.objects.find((obj) => obj.labels !== undefined);
    const stixWithoutLabel = data.objects.find((obj) => obj.labels === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['labelledBy'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'identity']
      };
      expect(testers.testLabel(stixWithLabel, filter)).toEqual(true);
    });
    it('should test positive for a stix object with matching filter', () => {
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
    const stixWithRevoked = data.objects.find((obj) => obj.revoked !== undefined);
    const stixWithoutRevoked = data.objects.find((obj) => obj.revoked === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['revoked'],
        mode: 'OR',
        operator: 'eq',
        values: ['false']
      };
      expect(testers.testRevoked(stixWithRevoked, filter)).toEqual(true);
    });
    it('should test positive for a stix object with matching filter', () => {
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

  // TODO: describe('Detection (key=x_opencti_detection)', () => { }); --> no data in DATA-TEST-STIX2_v2.json
  // TODO: describe('Score (key=x_opencti_score)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  describe('Confidence (key=confidence)', () => {
    const stixWithConfidence = data.objects.find((obj) => obj.confidence !== undefined);
    const stixWithoutConfidence = data.objects.find((obj) => obj.confidence === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['confidence'],
        mode: 'OR',
        operator: 'gt',
        values: ['50']
      };
      expect(testers.testConfidence(stixWithConfidence, filter)).toEqual(true);
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
    const stixWithPattern = data.objects.find((obj) => obj.pattern_type !== undefined);
    const stixWithoutPattern = data.objects.find((obj) => obj.pattern_type === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['stix']
      };
      expect(testers.testPattern(stixWithPattern, filter)).toEqual(true);
      const filterCase: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['StiX'] // tester should be case insensitive
      };
      expect(testers.testPattern(stixWithPattern, filterCase)).toEqual(true);
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
    const stixWithObjectRefs = data.objects.find((obj) => obj.object_refs !== undefined);
    const stixWithoutObjectRefs = data.objects.find((obj) => obj.object_refs === undefined);

    it('should test positive for a stix object with matching filter', () => {
      const filter: Filter = {
        key: ['pattern_type'],
        mode: 'OR',
        operator: 'eq',
        values: ['<some-id>', 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c']
      };
      expect(testers.testObjectContains(stixWithObjectRefs, filter)).toEqual(true);
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

  // TODO: describe('Severity (key=severity)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  // TODO: describe('Priority (key=priority)', () => { }); --> no data in DATA-TEST-STIX2_v2.json

  describe('Relationship', () => {
    const stixRelationship = data.objects.find((obj) => obj.type === 'relationship');

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
    const stixSighting = data.objects.find((obj) => obj.type === 'sighting');

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
    const stixWithExtId = data.objects.find((obj) => obj.extensions?.[STIX_EXT_OCTI]?.id !== undefined);
    const stixRelationship = data.objects.find((obj) => obj.type === 'relationship');

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
