import { assoc, map, values } from 'ramda';
import { executeRead, executeWrite } from '../database/grakn';

const inferences = {
  'b5c30c61-beb9-4d45-b742-701963ca1f9a': {
    id: 'b5c30c61-beb9-4d45-b742-701963ca1f9a',
    name: 'AttributionAttributionRule',
    rule:
      'AttributionAttributionRule sub rule,\n' +
      '    when {\n' +
      '      (origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      (origin: $entity, attribution: $subentity) isa attributed-to;\n' +
      '    }, then {\n' +
      '      (origin: $origin, attribution: $subentity) isa attributed-to;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is attributed to an entity B and the entity B is attributed to an entity C, the entity A is also attributed to the entity C.'
  },
  '2da36fdf-775f-48ad-a148-814c0cfec032': {
    id: '2da36fdf-775f-48ad-a148-814c0cfec032',
    name: 'AttributionUsesRule',
    rule:
      'AttributionUsesRule sub rule,\n' +
      '    when {\n' +
      '      (origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      (user: $entity, usage: $object) isa uses;\n' +
      '    }, then {\n' +
      '      (user: $origin, usage: $object) isa uses;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A uses an object B and the entity A is attributed to an entity C, the entity A is also using the object B.'
  },
  '3e5e7540-6eea-4e5f-b59d-d0c1b341c030': {
    id: '3e5e7540-6eea-4e5f-b59d-d0c1b341c030',
    name: 'AttributionTargetsRule',
    rule:
      'AttributionTargetsRule sub rule,\n' +
      '    when {\n' +
      '      (origin: $origin, attribution: $entity) isa attributed-to;\n' +
      '      (source: $entity, target: $target) isa targets;\n' +
      '    }, then {\n' +
      '      (source: $origin, target: $target) isa targets;\n' +
      '    };\n',
    description:
      'This rule can be used to infer the following fact: if an entity A targets an entity B and the entity A is attributed to an entity C, the entity C also targets the entity B.'
  },
  'fcbd7aa7-680c-4796-9572-03463956880b': {
    id: 'fcbd7aa7-680c-4796-9572-03463956880b',
    name: 'LocalizationLocalizationRule',
    rule:
      'LocalizationLocalizationRule sub rule,\n' +
      '    when {\n' +
      '      (location: $location, localized: $entity) isa localization;\n' +
      '      (location: $entity, localized: $subentity) isa localization;\n' +
      '    }, then {\n' +
      '      (location: $location, localized: $subentity) isa localization;\n' +
      '    };',
    description:
      'This rule can be used to infer the following fact: if an entity A is localized in an entity B and the entity B is localized in an entity C, then the entity A is also localized in the entity C.'
  }
};

export const findAll = async () => {
  const query = `match $r sub rule; get;`;
  const currentRules = await executeRead(async rTx => {
    const iterator = await rTx.tx.query(query);
    const answers = await iterator.collect();
    return Promise.all(
      answers.map(async answer => {
        const rule = answer.map().get('r');
        return rule.label();
      })
    );
  });
  return map(n => assoc('enabled', currentRules.includes(n.name), n), values(inferences));
};

export const inferenceEnable = async id => {
  const inference = inferences[id];
  if (inference) {
    const query = `define ${inference.rule}`;
    await executeWrite(async wTx => {
      wTx.tx.query(query);
    });
  }
  return assoc('enabled', true, inference);
};

export const inferenceDisable = async id => {
  const inference = inferences[id];
  if (inference) {
    const query = `undefine ${inference.name} sub rule;`;
    await executeWrite(async wTx => {
      wTx.tx.query(query);
    });
  }
  return assoc('enabled', false, inference);
};
