import { assoc, map, values } from 'ramda';
import { executeRead, executeWrite } from '../database/grakn';

export const PART_OF_TARGETS_RULE = '391d08b1-deb5-434f-9a5d-cc2441abd601';
const inferences = {
  'b5c30c61-beb9-4d45-b742-701963ca1f9a': {
    id: 'b5c30c61-beb9-4d45-b742-701963ca1f9a',
    name: 'AttributionAttributionRule',
    rule:
      'AttributionAttributionRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_attributed-to_from_attributed-to_to(attributed-to_from: $subEntity, attributed-to_to: $entity) isa attributed-to;\n' +
      '      $rel2_attributed-to_from_attributed-to_to(attributed-to_from: $entity, attributed-to_to: $parentEntity) isa attributed-to;\n' +
      '    }, then {\n' +
      '      (attributed-to_from: $subEntity, attributed-to_to: $parentEntity) isa attributed-to;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is attributed to an entity B and the entity B is attributed to an entity C, the entity A is also attributed to the entity C.',
  },
  '2da36fdf-775f-48ad-a148-814c0cfec032': {
    id: '2da36fdf-775f-48ad-a148-814c0cfec032',
    name: 'AttributionUsesRule',
    rule:
      'AttributionUsesRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_attributed-to_from_attributed-to_to(attributed-to_from: $subEntity, attributed-to_to: $entity) isa attributed-to;\n' +
      '      $rel2_uses_from_uses_to(uses_from: $subEntity, uses_to: $object) isa uses;\n' +
      '    }, then {\n' +
      '      (uses_from: $entity, uses_to: $object) isa uses;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A uses an object B and the entity A is attributed to an entity C, the entity C is also using the object B.',
  },
  '3e5e7540-6eea-4e5f-b59d-d0c1b341c030': {
    id: '3e5e7540-6eea-4e5f-b59d-d0c1b341c030',
    name: 'AttributionTargetsRule',
    rule:
      'AttributionTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_attributed-to_from_attributed-to_to(attributed-to_from: $subEntity, attributed-to_to: $entity) isa attributed-to;\n' +
      '      $rel2_targets_from_targets_to(targets_from: $subEntity, targets_to: $target) isa targets;\n' +
      '    }, then {\n' +
      '      (targets_from: $entity, targets_to: $target) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A targets an entity B and the entity A is attributed to an entity C, the entity C also targets the entity B.',
  },
  '266b1b3b-0c94-439e-bac0-e14130bb1465': {
    id: '266b1b3b-0c94-439e-bac0-e14130bb1465',
    name: 'PartOfPartOfRule',
    rule:
      'PartOfPartOfRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_part-of_from_part-of_to(part-of_from: $subLocation, part-of_to: $location) isa part-of;\n' +
      '      $rel2_part-of_from_part-of_to(part-of_from: $location, part-of_to: $parentLocation) isa part-of;\n' +
      '    }, then {\n' +
      '      (part-of_from: $subLocation, part-of_to: $parentLocation) isa part-of;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is part of an entity B and the entity B is part of an entity C, then the entity A is also part of the entity C.',
  },
  'fcbd7aa7-680c-4796-9572-03463956880b': {
    id: 'fcbd7aa7-680c-4796-9572-03463956880b',
    name: 'LocatedAtLocatedAtRule',
    rule:
      'LocatedAtLocatedAtRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_located-at_from_located-at_to(located-at_from: $subLocation, located-at_to: $location) isa located-at;\n' +
      '      $rel2_located-at_from_located-at_to(located-at_from: $location, located-at_to: $parentLocation) isa located-at;\n' +
      '    }, then {\n' +
      '      (located-at_from: $subLocation, located-at_to: $parentLocation) isa located-at;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is located at an entity B and the entity B is located at an entity C, then the entity A is also located at the entity C.',
  },
  'e6a6989b-7992-4f7e-9f07-741145423181': {
    id: 'e6a6989b-7992-4f7e-9f07-741145423181',
    name: 'LocationOfTargetsRule',
    rule:
      '    LocationOfTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_targets_from_targets_to(targets_from: $entity, targets_to: $target) isa targets;\n' +
      '      $rel2_located-at_from_located-at_to(located-at_from: $rel1_targets_from_targets_to, located-at_to: $location) isa located-at;\n' +
      '    }, then {\n' +
      '      (targets_from: $entity, targets_to: $location) isa targets;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A targets an entity B through a relation X, and the relation X is located at an entity C, then the entity A also targets the entity C.',
  },
  [PART_OF_TARGETS_RULE]: {
    id: PART_OF_TARGETS_RULE,
    name: 'PartOfTargetsRule',
    rule:
      '    PartOfTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_part-of_from_part-of_to(part-of_from: $subEntity, part-of_to: $entity) isa part-of;\n' +
      '      $rel2_source_target(targets_from: $threat, targets_to: $subEntity) isa targets;\n' +
      '    }, then {\n' +
      '      (targets_from: $threat, targets_to: $entity) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A is part of an entity B, and the entity C targets the entity A, then the entity C targets the entity B.',
  },
  'ca789b78-775d-4a84-bc3e-ffd88d1c35c5': {
    id: 'ca789b78-775d-4a84-bc3e-ffd88d1c35c5',
    name: 'MalwareUsageTargetsRule',
    rule:
      '    MalwareUsageTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $malware isa Malware;\n' +
      '      $incident isa X-OpenCTI-Incident;\n' +
      '      $rel1_targets_from_targets_to(targets_from: $incident, targets_to: $target) isa targets;\n' +
      '      $rel2_uses_from_uses_to(uses_from: $incident, uses_to: $malware) isa uses;\n' +
      '    }, then {\n' +
      '      (targets_from: $malware, targets_to: $target) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A is an Incident and targets an entity B, and the entity A uses a malware C, then the malware C targets the entity B.',
  },
};

export const findAll = async () => {
  const query = `match $r sub rule; get;`;
  const currentRules = await executeRead(async (rTx) => {
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    return Promise.all(
      answers.map(async (answer) => {
        const rule = answer.map().get('r');
        return rule.label();
      })
    );
  });
  return map((n) => assoc('enabled', currentRules.includes(n.name), n), values(inferences));
};

export const inferenceEnable = async (id) => {
  const inference = inferences[id];
  if (inference) {
    const query = `define ${inference.rule}`;
    await executeWrite(async (wTx) => {
      wTx.query(query);
    });
  }
  return assoc('enabled', true, inference);
};

export const inferenceDisable = async (id) => {
  const inference = inferences[id];
  if (inference) {
    const query = `undefine ${inference.name} sub rule;`;
    await executeWrite(async (wTx) => {
      wTx.query(query);
    });
  }
  return assoc('enabled', false, inference);
};