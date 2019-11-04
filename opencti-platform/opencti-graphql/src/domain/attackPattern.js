import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  getById,
  graknNow,
  monthFormat,
  notify,
  paginate,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';
import {
  linkCreatedByRef,
  linkKillChains,
  linkMarkingDef,
  linkTags
} from './stixEntity';

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

export const findByCourseOfAction = args => {
  return paginate(
    `match $a isa Attack-Pattern;
    $rel(problem:$a, mitigation:$c) isa mitigates;
    $c has internal_id_key "${escapeString(args.courseOfActionId)}"`,
    args
  );
};

export const findById = attackPatternId => getById(attackPatternId);

export const addAttackPattern = async (user, attackPattern) => {
  const patternId = await executeWrite(async wTx => {
    const internalId = attackPattern.internal_id_key
      ? escapeString(attackPattern.internal_id_key)
      : uuid();
    const query = `insert $attackPattern isa Attack-Pattern,
    has internal_id_key "${internalId}",
    has entity_type "attack-pattern",
    has stix_id_key "${
      attackPattern.stix_id_key
        ? escapeString(attackPattern.stix_id_key)
        : `attack-pattern--${uuid()}`
    }",
    has stix_label "",
    ${
      attackPattern.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(attackPattern.alias)
            )
          )} has alias "${escapeString(head(attackPattern.alias))}",`
        : 'has alias "",'
    }
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
    const createAttack = await attackPatternIterator.next();
    const attackPatternId = await createAttack.map().get('attackPattern').id;

    // Create associated relations
    await linkCreatedByRef(wTx, attackPatternId, attackPattern.createdByRef);
    await linkMarkingDef(
      wTx,
      attackPatternId,
      attackPattern.markingDefinitions
    );
    await linkKillChains(wTx, attackPatternId, attackPattern.killChainPhases);
    await linkTags(wTx, attackPatternId, attackPattern.tags);
    return internalId;
  });
  return getById(patternId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
