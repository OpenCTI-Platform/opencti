import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  monthFormat,
  notify,
  now,
  paginate,
  takeTx,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa CourseOfAction', args);

export const findById = courseOfActionId => loadByID(courseOfActionId);

export const addCourseOfAction = async (user, courseOfAction) => {
  const wTx = await takeTx();
  const courseOfActionIterator = await wTx.query(`insert $courseOfAction isa CourseOfAction 
    has type "courseOfAction";
    $courseOfAction has stix_id "courseOfAction--${uuid()}";
    $courseOfAction has stix_label "";
    $courseOfAction has stix_label_lowercase "";
    $courseOfAction has alias "";
    $courseOfAction has alias_lowercase "";
    $courseOfAction has name "${courseOfAction.name}";
    $courseOfAction has description "${courseOfAction.description}";
    $courseOfAction has name_lowercase "${courseOfAction.name.toLowerCase()}";
    $courseOfAction has description_lowercase "${
      courseOfAction.description ? courseOfAction.description.toLowerCase() : ''
    }";
    $courseOfAction has created ${now()};
    $courseOfAction has modified ${now()};
    $courseOfAction has revoked false;
    $courseOfAction has created_at ${now()};
    $courseOfAction has created_at_month "${monthFormat(now())}";
    $courseOfAction has created_at_year "${yearFormat(now())}";    
    $courseOfAction has updated_at ${now()};
  `);
  const createCourseOfAction = await courseOfActionIterator.next();
  const createdCourseOfActionId = await createCourseOfAction
    .map()
    .get('courseOfAction').id;

  if (courseOfAction.createdByRef) {
    await wTx.query(`match $from id ${createdCourseOfActionId};
         $to id ${courseOfAction.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (courseOfAction.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdCourseOfActionId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      courseOfAction.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (courseOfAction.killChainPhases) {
    const createKillChainPhase = killChainPhase =>
      wTx.query(
        `match $from id ${createdCourseOfActionId}; $to id ${killChainPhase}; insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases;`
      );
    const killChainPhasesPromises = map(
      createKillChainPhase,
      courseOfAction.killChainPhases
    );
    await Promise.all(killChainPhasesPromises);
  }

  await wTx.commit();

  return loadByID(createdCourseOfActionId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const courseOfActionDelete = courseOfActionId =>
  deleteByID(courseOfActionId);
