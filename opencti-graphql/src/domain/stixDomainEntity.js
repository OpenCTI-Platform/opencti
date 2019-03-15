import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteEntityById,
  deleteRelation,
  editInputTx,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeWriteTx,
  timeSeries,
  getObject,
  prepareString,
  getSingleValueNumber,
  prepareDate
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';

export const findAll = args =>
  paginate(
    `match $m isa ${args.type ? args.type : 'Stix-Domain-Entity'}`,
    args,
    false
  );

export const stixDomainEntitiesTimeSeries = args =>
  timeSeries(
    `match $x isa ${args.type ? args.type : 'Stix-Domain-Entity'}`,
    args
  );

export const stixDomainEntitiesNumber = args => ({
  count: getSingleValueNumber(
    `match $x isa ${args.type ? args.type : 'Stix-Domain-Entity'}; ${
      args.endDate
        ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};`
        : ''
    } aggregate count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${
      args.type ? args.type : 'Stix-Domain-Entity'
    }; aggregate count;`
  )
});

export const findById = stixDomainEntityId => getById(stixDomainEntityId);

export const findByName = args =>
  paginate(
    `match $m isa ${
      args.type ? args.type : 'Stix-Domain-Entity'
    }; $m has name "${prepareString(args.name)}"`,
    args,
    false
  );

export const findByExternalReference = args =>
  paginate(
    `match $stixDomainEntity isa ${
      args.type ? args.type : 'Stix-Domain-Entity'
    };
     $rel(external_reference:$externalReference, so:$stixDomainEntity) isa external_references;
     $externalReference id "${prepareString(args.externalReferenceId)}"`,
    args,
    false
  );

export const search = args =>
  paginate(
    `match $m isa ${args.type ? args.type : 'Stix-Domain-Entity'}
    has name $name;
    $m has alias $alias;
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const createdByRef = stixDomainEntityId =>
  getObject(
    `match $x isa Identity; 
    $rel(creator:$x, so:$stixDomainEntity) isa created_by_ref; 
    $stixDomainEntity id ${stixDomainEntityId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const killChainPhases = (stixDomainEntityId, args) =>
  paginate(
    `match $kc isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$kc, phase_belonging:$stixDomainEntity) isa kill_chain_phases; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args,
    false
  );

export const markingDefinitions = (stixDomainEntityId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixDomainEntity) isa object_marking_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args,
    false
  );

export const reports = (stixDomainEntityId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixDomainEntity) isa object_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const reportsTimeSeries = (stixDomainEntityId, args) =>
  timeSeries(
    `match $m isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixDomainEntity) isa object_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const externalReferences = (stixDomainEntityId, args) =>
  paginate(
    `match $externalReference isa External-Reference; 
    $rel(external_reference:$externalReference, so:$stixDomainEntity) isa external_references; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args,
    false
  );

export const stixRelations = (stixDomainEntityId, args) => {
  const finalArgs = assoc('fromId', stixDomainEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const wTx = await takeWriteTx();
  const stixDomainEntityIterator = await wTx.query(`insert $stixDomainEntity isa ${
    stixDomainEntity.type
  } 
    has type "${prepareString(stixDomainEntity.type.toLowerCase())}";
    $stixDomainEntity has stix_id "${prepareString(
      stixDomainEntity.type.toLowerCase()
    )}--${uuid()}";
    $stixDomainEntity has stix_label "";
    $stixDomainEntity has alias "";
    $stixDomainEntity has name "${prepareString(stixDomainEntity.name)}";
    $stixDomainEntity has description "${prepareString(
      stixDomainEntity.description
    )}";
    $stixDomainEntity has created ${now()};
    $stixDomainEntity has modified ${now()};
    $stixDomainEntity has revoked false;
    $stixDomainEntity has created_at ${now()};
    $stixDomainEntity has created_at_day "${dayFormat(now())}";
    $stixDomainEntity has created_at_month "${monthFormat(now())}";
    $stixDomainEntity has created_at_year "${yearFormat(now())}";      
    $stixDomainEntity has updated_at ${now()};
  `);
  const createStixDomainEntity = await stixDomainEntityIterator.next();
  const createdStixDomainEntityId = await createStixDomainEntity
    .map()
    .get('stixDomainEntity').id;

  if (stixDomainEntity.createdByRef) {
    await wTx.query(`match $from id ${createdStixDomainEntityId};
         $to id ${stixDomainEntity.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (stixDomainEntity.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdStixDomainEntityId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixDomainEntity.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdStixDomainEntityId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const stixDomainEntityDelete = stixDomainEntityId =>
  deleteEntityById(stixDomainEntityId);

export const stixDomainEntityAddRelation = (user, stixDomainEntityId, input) =>
  createRelation(stixDomainEntityId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityDeleteRelation = (
  user,
  stixDomainEntityId,
  relationId
) =>
  deleteRelation(stixDomainEntityId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return getById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditContext = (
  user,
  stixDomainEntityId,
  input
) => {
  setEditContext(user, stixDomainEntityId, input);
  return getById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditField = (user, stixDomainEntityId, input) =>
  editInputTx(stixDomainEntityId, input).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
