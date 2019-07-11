import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  takeWriteTx,
  commitWriteTx,
  paginate
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix-domain-entities', assoc('type', 'course-of-action', args));
// paginate('match $c isa Course-Of-Action', args);

export const search = args =>
  elPaginate('stix-domain-entities', assoc('type', 'course-of-action', args));

export const findByEntity = args =>
  paginate(
    `match $c isa Course-Of-Action; 
    $rel(mitigation:$c, problem:$p) isa mitigates;
    $p has internal_id "${escapeString(args.objectId)}"`,
    args
  );

export const findById = courseOfActionId => getById(courseOfActionId);

export const addCourseOfAction = async (user, courseOfAction) => {
  const wTx = await takeWriteTx();
  const internalId = courseOfAction.internal_id
    ? escapeString(courseOfAction.internal_id)
    : uuid();
  const courseOfActionIterator = await wTx.tx
    .query(`insert $courseOfAction isa Course-Of-Action,
    has internal_id "${internalId}",
    has entity_type "course-of-action",
    has stix_id "${
      courseOfAction.stix_id
        ? escapeString(courseOfAction.stix_id)
        : `course-of-action--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(courseOfAction.name)}",
    has description "${escapeString(courseOfAction.description)}",
    has created ${
      courseOfAction.created ? prepareDate(courseOfAction.created) : now()
    },
    has modified ${
      courseOfAction.modified ? prepareDate(courseOfAction.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",  
    has updated_at ${now()};
  `);
  const createCourseOfAction = await courseOfActionIterator.next();
  const createdCourseOfActionId = await createCourseOfAction
    .map()
    .get('courseOfAction').id;

  if (courseOfAction.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdCourseOfActionId};
      $to has internal_id "${escapeString(courseOfAction.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (courseOfAction.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdCourseOfActionId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      courseOfAction.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (courseOfAction.killChainPhases) {
    const createKillChainPhase = killChainPhase =>
      wTx.tx.query(
        `match $from id ${createdCourseOfActionId};
         $to has internal_id "${escapeString(killChainPhase)}"; 
         insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases, has internal_id "${uuid()}";`
      );
    const killChainPhasesPromises = map(
      createKillChainPhase,
      courseOfAction.killChainPhases
    );
    await Promise.all(killChainPhasesPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
