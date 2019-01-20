import { map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qkObjUnique,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa CourseOfAction', args);

export const findById = courseOfActionId => loadByID(courseOfActionId);

export const createdByRef = courseOfActionId =>
  qkObjUnique(
    `match $x isa Identity; 
    $rel(creator:$x, so:$courseOfAction) isa created_by_ref; 
    $courseOfAction id ${courseOfActionId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const markingDefinitions = (courseOfActionId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$courseOfAction) isa object_marking_refs; 
    $courseOfAction id ${courseOfActionId}`,
    args
  );

export const reports = (courseOfActionId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$courseOfAction) isa object_refs; 
    $courseOfAction id ${courseOfActionId}`,
    args
  );

export const addCourseOfAction = async (user, courseOfAction) => {
  const wTx = await takeTx();
  const courseOfActionIterator = await wTx.query(`insert $courseOfAction isa CourseOfAction 
    has type "courseOfAction";
    $courseOfAction has stix_id "courseOfAction--${uuid()}";
    $courseOfAction has name "${courseOfAction.name}";
    $courseOfAction has description "${courseOfAction.description}";
    $courseOfAction has created ${now()};
    $courseOfAction has modified ${now()};
    $courseOfAction has revoked false;
    $courseOfAction has created_at ${now()};
    $courseOfAction has updated_at ${now()};
  `);
  const createCourseOfAction = await courseOfActionIterator.next();
  const createdCourseOfActionId = await createCourseOfAction.map().get('courseOfAction').id;

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
    notify(BUS_TOPICS.CourseOfAction.ADDED_TOPIC, created, user)
  );
};

export const courseOfActionDelete = courseOfActionId => deleteByID(courseOfActionId);

export const courseOfActionAddRelation = (user, courseOfActionId, input) =>
  createRelation(courseOfActionId, input).then(relationData => {
    notify(BUS_TOPICS.CourseOfAction.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const courseOfActionDeleteRelation = (user, courseOfActionId, relationId) =>
  deleteRelation(courseOfActionId, relationId).then(relationData => {
    notify(BUS_TOPICS.CourseOfAction.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const courseOfActionCleanContext = (user, courseOfActionId) => {
  delEditContext(user, courseOfActionId);
  return loadByID(courseOfActionId).then(courseOfAction =>
    notify(BUS_TOPICS.CourseOfAction.EDIT_TOPIC, courseOfAction, user)
  );
};

export const courseOfActionEditContext = (user, courseOfActionId, input) => {
  setEditContext(user, courseOfActionId, input);
  return loadByID(courseOfActionId).then(courseOfAction =>
    notify(BUS_TOPICS.CourseOfAction.EDIT_TOPIC, courseOfAction, user)
  );
};

export const courseOfActionEditField = (user, courseOfActionId, input) =>
  editInputTx(courseOfActionId, input).then(courseOfAction =>
    notify(BUS_TOPICS.CourseOfAction.EDIT_TOPIC, courseOfAction, user)
  );
