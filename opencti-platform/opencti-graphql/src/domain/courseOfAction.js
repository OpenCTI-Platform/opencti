import { assoc } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  paginate,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { addCreatedByRef, addKillChains, addMarkingDefs } from './stixEntity';
import { notify } from '../database/redis';

export const findById = courseOfActionId => {
  return loadEntityById(courseOfActionId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'course-of-action', args));
};

export const findByEntity = args => {
  return paginate(
    `match $c isa Course-Of-Action; 
    $rel(mitigation:$c, problem:$p) isa mitigates;
    $p has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const internalId = courseOfAction.internal_id_key ? escapeString(courseOfAction.internal_id_key) : uuid();
  const courseId = await executeWrite(async wTx => {
    const now = graknNow();
    const courseOfActionIterator = await wTx.tx.query(`insert $courseOfAction isa Course-Of-Action,
    has internal_id_key "${internalId}",
    has entity_type "course-of-action",
    has stix_id_key "${
      courseOfAction.stix_id_key ? escapeString(courseOfAction.stix_id_key) : `course-of-action--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(courseOfAction.name)}",
    has description "${escapeString(courseOfAction.description)}",
    has created ${courseOfAction.created ? prepareDate(courseOfAction.created) : now},
    has modified ${courseOfAction.modified ? prepareDate(courseOfAction.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",  
    has updated_at ${now};
  `);
    const createCourseOfAction = await courseOfActionIterator.next();
    return createCourseOfAction.map().get('courseOfAction').id;
  });
  const created = await loadEntityById(courseId);
  await addCreatedByRef(internalId, courseOfAction.createdByRef);
  await addMarkingDefs(internalId, courseOfAction.markingDefinitions);
  await addKillChains(internalId, courseOfAction.killChainPhases);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
