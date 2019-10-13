import { assoc, map, join } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  graknNow,
  paginate,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args => {
  if (args.orderBy === 'killChainPhases') {
    const finalArgs = assoc('orderBy', 'phase_name', args);
    return paginate(
      `match $a isa Attack-Pattern; 
      $rel(kill_chain_phase:$x, phase_belonging:$a) isa kill_chain_phases`,
      finalArgs,
      true,
      'x'
    );
  }
  return elPaginate(
    'stix_domain_entities',
    assoc('type', 'attack-pattern', args)
  );
};

export const findById = attackPatternId => getById(attackPatternId);

export const addAttackPattern = async (user, attackPattern) => {
  const wTx = await takeWriteTx();
  const internalId = attackPattern.internal_id
    ? escapeString(attackPattern.internal_id)
    : uuid();
  const query = `insert $attackPattern isa Attack-Pattern,
    has internal_id "${internalId}",
    has entity_type "attack-pattern",
    has stix_id "${
      attackPattern.stix_id
        ? escapeString(attackPattern.stix_id)
        : `attack-pattern--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(attackPattern.name)}",
    has description "${escapeString(attackPattern.description)}",
    ${
      attackPattern.platform
        ? join(
            ' ',
            map(
              platform => `has platform "${escapeString(platform)}",`,
              attackPattern.platform
            )
          )
        : ''
    }
    ${
      attackPattern.required_permission
        ? join(
            ' ',
            map(
              requiredPermission =>
                `has required_permission "${escapeString(
                  requiredPermission
                )}",`,
              attackPattern.required_permission
            )
          )
        : ''
    }
    has created ${
      attackPattern.created ? prepareDate(attackPattern.created) : graknNow()
    },
    has modified ${
      attackPattern.modified ? prepareDate(attackPattern.modified) : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",
    has updated_at ${graknNow()};
  `;
  logger.debug(`[GRAKN - infer: false] addAttackPattern > ${query}`);
  const attackPatternIterator = await wTx.tx.query(query);
  const createAttackPattern = await attackPatternIterator.next();
  const createdAttackPatternId = await createAttackPattern
    .map()
    .get('attackPattern').id;

  if (attackPattern.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdAttackPatternId};
      $to has internal_id "${escapeString(attackPattern.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (attackPattern.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdAttackPatternId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      attackPattern.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (attackPattern.killChainPhases) {
    const createKillChainPhase = killChainPhase =>
      wTx.tx.query(
        `match $from id ${createdAttackPatternId}; 
        $to has internal_id "${escapeString(killChainPhase)}";
        insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases, has internal_id "${uuid()}";`
      );
    const killChainPhasesPromises = map(
      createKillChainPhase,
      attackPattern.killChainPhases
    );
    await Promise.all(killChainPhasesPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
