import { assoc, map, values } from 'ramda';
import { executeRead, executeWrite } from '../database/grakn';

export const GATHERING_TARGETS_RULE = '391d08b1-deb5-434f-9a5d-cc2441abd601';
const inferences = {
  'b5c30c61-beb9-4d45-b742-701963ca1f9a': {
    id: 'b5c30c61-beb9-4d45-b742-701963ca1f9a',
    name: 'AttributionAttributionRule',
    rule:
      'AttributionAttributionRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_attribution_origin(origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      $rel2_attribution_origin(origin: $entity, attribution: $subentity) isa attributed-to;\n' +
      '    }, then {\n' +
      '      (origin: $origin, attribution: $subentity) isa attributed-to;\n' +
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
      '      $rel1_attribution_origin(origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      $rel2_user_usage(user: $entity, usage: $object) isa uses;\n' +
      '    }, then {\n' +
      '      (user: $origin, usage: $object) isa uses;\n' +
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
      '      $rel1_attribution_origin(origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      $rel2_source_target(source: $entity, target: $target) isa targets;\n' +
      '    }, then {\n' +
      '      (source: $origin, target: $target) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A targets an entity B and the entity A is attributed to an entity C, the entity C also targets the entity B.',
  },
  'fcbd7aa7-680c-4796-9572-03463956880b': {
    id: 'fcbd7aa7-680c-4796-9572-03463956880b',
    name: 'LocalizationLocalizationRule',
    rule:
      'LocalizationLocalizationRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_localized_location(location: $location, localized: $entity) isa localization;\n' +
      '      $rel2_localized_location(location: $entity, localized: $subentity) isa localization;\n' +
      '    }, then {\n' +
      '      (location: $location, localized: $subentity) isa localization;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is localized in an entity B and the entity B is localized in an entity C, then the entity A is also localized in the entity C.',
  },
  'e6a6989b-7992-4f7e-9f07-741145423181': {
    id: 'e6a6989b-7992-4f7e-9f07-741145423181',
    name: 'LocalizationOfTargetsRule',
    rule:
      '    LocalizationOfTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_source_target(source: $entity, target: $target) isa targets;\n' +
      '      $rel2_localized_location(location: $location, localized: $rel1_source_target) isa localization;\n' +
      '    }, then {\n' +
      '      (source: $entity, target: $location) isa targets;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A targets an entity B through a relation X, and the relation X is located in an entity C, then the entity A also targets the entity C.',
  },
  [GATHERING_TARGETS_RULE]: {
    id: GATHERING_TARGETS_RULE,
    name: 'GatheringTargetsRule',
    rule:
      '    GatheringTargetsRule sub rule,\n' +
      '    when {\n' +
      '      $rel1_part-of_gather(gather: $parent, part_of: $entity) isa gathering;\n' +
      '      $rel2_source_target(source: $source, target: $entity) isa targets;\n' +
      '    }, then {\n' +
      '      (source: $source, target: $parent) isa targets;\n' +
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
      '      $user isa Incident;\n' +
      '      $rel1_source_target(source: $user, target: $target) isa targets;\n' +
      '      $rel2_user_usage(user: $user, usage: $malware) isa uses;\n' +
      '    }, then {\n' +
      '      (source: $malware, target: $target) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A is an Incident and targets an entity B, and the entity A uses a malware C, then the malware C targets the entity B.',
  },
};

export const findAll = async () => {
  const query = `match $r sub rule; get;`;
  const currentRules = await executeRead(async (rTx) => {
    const iterator = await rTx.tx.query(query);
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
      wTx.tx.query(query);
    });
  }
  return assoc('enabled', true, inference);
};

export const inferenceDisable = async (id) => {
  const inference = inferences[id];
  if (inference) {
    const query = `undefine ${inference.name} sub rule;`;
    await executeWrite(async (wTx) => {
      wTx.tx.query(query);
    });
  }
  return assoc('enabled', false, inference);
};
