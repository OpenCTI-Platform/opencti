import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  takeWriteTx,
  deleteEntityById,
  getById,
  notify,
  now,
  paginate,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $t isa Threat-Actor', args);

export const search = args =>
  paginate(
    `match $t isa Threat-Actor;
    $t has name $name;
    $t has alias $alias;
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const findById = threatActorId => getById(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const wTx = await takeWriteTx();
  const threatActorIterator = await wTx.query(`insert $threatActor isa Threat-Actor,
    has entity_type "threat-actor",
    has stix_id "${
      threatActor.stix_id
        ? prepareString(threatActor.stix_id)
        : `threat-actor--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(threatActor.name)}",
    has description "${prepareString(threatActor.description)}",
    has goal "${prepareString(threatActor.goal)}",
    has sophistication "${prepareString(threatActor.sophistication)}",
    has resource_level "${prepareString(threatActor.resource_level)}",
    has primary_motivation "${prepareString(threatActor.primary_motivation)}",
    has secondary_motivation "${prepareString(
      threatActor.secondary_motivation
    )}",
    has personal_motivation "${prepareString(threatActor.personal_motivation)}",
    has created ${
      threatActor.created ? prepareDate(threatActor.created) : now()
    },
    has modified ${
      threatActor.modified ? prepareDate(threatActor.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",        
    has updated_at ${now()};
  `);
  const createThreatActor = await threatActorIterator.next();
  const createThreatActorId = await createThreatActor.map().get('threatActor')
    .id;

  if (threatActor.createdByRef) {
    await wTx.query(
      `match $from id ${createThreatActorId};
      $to id ${threatActor.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (threatActor.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createThreatActorId};
        $to id ${markingDefinition};
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      threatActor.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createThreatActorId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const threatActorDelete = threatActorId =>
  deleteEntityById(threatActorId);
