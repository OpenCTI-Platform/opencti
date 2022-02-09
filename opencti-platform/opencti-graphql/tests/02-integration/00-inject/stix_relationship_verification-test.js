import { stixCoreRelationshipsMapping, stixCyberObservableRelationshipsMapping } from '../../../src/database/stix';

import stixRelationships from '../../data/stix_relationships.json';

const openctiStixMapping = {
  identity: ['individual', 'organization', 'sector'],
  location: ['region', 'country', 'city', 'position'],
  file: ['stixfile'],
};

const openctiRelationshipException = {
  'threat-actor_sector': ['attributed-to', 'impersonates'],
};

describe('Test that all STIX relationships are correctly implemented', () => {
  const combinedStixRelationshipMapping = {
    ...stixCyberObservableRelationshipsMapping,
    ...stixCoreRelationshipsMapping,
  };

  const lowerCaseOpenctiRelationship = Object.fromEntries(
    Object.entries(combinedStixRelationshipMapping).map(([key, val]) => [key.toLowerCase(), val])
  );

  let processedRelationships = [];
  Object.entries(stixRelationships).forEach(([sourceObject, targetAndRelationships]) => {
    Object.entries(targetAndRelationships).forEach(([targetObject, stixRelationship]) => {
      let sources = [sourceObject];
      if (sourceObject in openctiStixMapping) {
        sources = openctiStixMapping[sourceObject];
      }
      let targets = [targetObject];
      if (targetObject in openctiStixMapping) {
        targets = openctiStixMapping[targetObject];
      }

      sources.forEach((source) => {
        targets.forEach((target) => {
          const relationshipName = `${source}_${target}`;
          it(`Verifying that ${relationshipName} is implemented in OpenCTI`, () => {
            expect(Object.keys(lowerCaseOpenctiRelationship)).toContain(relationshipName);
          });

          let ctiRelationships = stixRelationship;
          if (relationshipName in openctiRelationshipException) {
            ctiRelationships = ctiRelationships.filter(
              (n) => !openctiRelationshipException[relationshipName].includes(n)
            );
          }
          it(`Verifying that ${relationshipName} contains all STIX relationships`, () => {
            expect(lowerCaseOpenctiRelationship[relationshipName]).toEqual(ctiRelationships);
          });
          processedRelationships = [...processedRelationships, relationshipName];
        });
      });
    });
  });

  it('Verifying that all STIX Relationships are implemented in OpenCTI', () => {
    expect(Object.keys(lowerCaseOpenctiRelationship)).toEqual(expect.arrayContaining(processedRelationships));
  });
});
