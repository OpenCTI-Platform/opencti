import { dissoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import { BUS_TOPICS, logger } from '../config/conf';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  getGraknId,
  graknNow,
  monthFormat,
  notify,
  paginate,
  prepareDate,
  refetchEntityById,
  timeSeries,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import {
  countEntities,
  deleteEntity,
  loadById,
  loadByStixId,
  paginate as elPaginate
} from '../database/elasticSearch';

import { generateFileExportName, upload } from '../database/minio';
import { connectorsForExport } from './connector';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => elPaginate('stix_domain_entities', args);

export const stixDomainEntitiesTimeSeries = args => {
  return timeSeries(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'}`,
    args
  );
};

export const stixDomainEntitiesNumber = args => ({
  count: countEntities('stix_domain_entities', args),
  total: countEntities('stix_domain_entities', dissoc('endDate', args))
});

export const findById = stixDomainEntityId => loadById(stixDomainEntityId);

export const findByStixId = args => loadByStixId(args.stix_id_key);

export const findByName = args => {
  // const index = inferIndexFromConceptTypes(['Stix-Domain-Entity']);
  // return findByTerms(
  //     [
  //       { 'name.keyword': escapeString(args.name) },
  //       { 'alias.keyword': escapeString(args.name) }
  //     ],
  //     index
  // );
  return paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
   $x has name $name;
   $x has alias $alias;
   { $name "${escapeString(args.name)}"; } or
   { $alias "${escapeString(args.name)}"; }`,
    args,
    false
  );
};

export const findByExternalReference = args => {
  return paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
     $rel(external_reference:$externalReference, so:$x) isa external_references;
     $externalReference has internal_id_key "${escapeString(
       args.externalReferenceId
     )}"`,
    args,
    false
  );
};

export const killChainPhases = (stixDomainEntityId, args) => {
  return paginate(
    `match $k isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$k, phase_belonging:$x) isa kill_chain_phases; 
    $x has internal_id_key "${escapeString(stixDomainEntityId)}"`,
    args,
    false,
    false
  );
};

export const reportsTimeSeries = (stixDomainEntityId, args) => {
  return timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(stixDomainEntityId)}"`,
    args
  );
};

export const externalReferences = (stixDomainEntityId, args) => {
  return paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$x) isa external_references; 
    $x has internal_id_key "${escapeString(stixDomainEntityId)}"`,
    args,
    false
  );
};

const askJobExports = async (entity, format, exportType) => {
  const connectors = await connectorsForExport(format, true);
  // Create job for every connectors
  const workList = await Promise.all(
    map(connector => {
      const fileName = generateFileExportName(
        format,
        connector,
        exportType,
        entity
      );
      return createWork(connector, entity.id, fileName).then(
        ({ work, job }) => ({
          connector,
          job,
          work
        })
      );
    }, connectors)
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map(data => {
      const { connector, job, work } = data;
      const message = {
        work_id: work.internal_id_key, // work(id)
        job_id: job.internal_id_key, // job(id)
        export_type: exportType, // simple or full
        entity_type: entity.entity_type, // report, threat, ...
        entity_id: entity.id, // report(id), thread(id), ...
        file_name: work.work_file // Base path for the upload
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};

export const stixDomainEntityImportPush = (user, entityId, file) => {
  return upload(user, 'import', file, entityId);
};

/**
 * Create export element waiting for completion
 * @param domainEntityId
 * @param format
 * @param exportType > stix2-bundle-full | stix2-bundle-simple
 * @returns {*}
 */
export const stixDomainEntityExportAsk = async (
  domainEntityId,
  format,
  exportType
) => {
  const entity = await refetchEntityById(domainEntityId);
  const workList = await askJobExports(entity, format, exportType);
  // Return the work list to do
  return map(w => workToExportFile(w.work), workList);
};

export const stixDomainEntityExportPush = async (user, entityId, file) => {
  // Upload the document in minio
  await upload(user, 'export', file, entityId);
  return refetchEntityById(entityId).then(stixDomainEntity => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user);
    return true;
  });
};

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const domainId = await executeWrite(async wTx => {
    const internalId = stixDomainEntity.internal_id_key
      ? escapeString(stixDomainEntity.internal_id_key)
      : uuid();
    const query = `insert $stixDomainEntity isa ${escape(
      stixDomainEntity.type
    )},
    has internal_id_key "${internalId}",
    has entity_type "${escapeString(stixDomainEntity.type.toLowerCase())}",
    has stix_id_key "${
      stixDomainEntity.stix_id_key
        ? escapeString(stixDomainEntity.stix_id_key)
        : `${escapeString(stixDomainEntity.type.toLowerCase())}--${uuid()}`
    }",
    has stix_label "",
    ${
      stixDomainEntity.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(stixDomainEntity.alias)
            )
          )} has alias "${escapeString(head(stixDomainEntity.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(stixDomainEntity.name)}",
    has description "${escapeString(stixDomainEntity.description)}",
    has created ${
      stixDomainEntity.created
        ? prepareDate(stixDomainEntity.created)
        : graknNow()
    },
    has modified ${
      stixDomainEntity.modified
        ? prepareDate(stixDomainEntity.modified)
        : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",      
    has updated_at ${graknNow()};
  `;
    logger.debug(`[GRAKN - infer: false] addStixDomainEntity > ${query}`);
    const stixDomainEntityIterator = await wTx.tx.query(query);
    const createSDO = await stixDomainEntityIterator.next();
    const createdId = await createSDO.map().get('stixDomainEntity').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdId, stixDomainEntity.createdByRef);
    await linkMarkingDef(wTx, createdId, stixDomainEntity.markingDefinitions);
    return internalId;
  });
  return refetchEntityById(domainId, true).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};

export const stixDomainEntityDelete = async stixDomainEntityId => {
  const graknId = await getGraknId(stixDomainEntityId);
  await deleteEntity('stix_domain_entities', graknId);
  return deleteEntityById(stixDomainEntityId);
};

export const stixDomainEntityAddRelation = (user, stixDomainEntityId, input) =>
  createRelation(stixDomainEntityId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityAddRelations = async (
  user,
  stixDomainEntityId,
  input
) => {
  const finalInput = map(
    n => ({
      toId: n,
      fromRole: input.fromRole,
      toRole: input.toRole,
      through: input.through
    }),
    input.toIds
  );
  const createRelationPromise = relationInput =>
    createRelation(stixDomainEntityId, relationInput);
  const relationsPromises = map(createRelationPromise, finalInput);
  await Promise.all(relationsPromises);
  return refetchEntityById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityDeleteRelation = (
  user,
  stixDomainEntityId,
  relationId
) =>
  deleteRelationById(stixDomainEntityId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return loadById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditContext = (
  user,
  stixDomainEntityId,
  input
) => {
  setEditContext(user, stixDomainEntityId, input);
  return loadById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditField = async (
  user,
  stixDomainEntityId,
  input
) => {
  return executeWrite(wTx => {
    return updateAttribute(stixDomainEntityId, input, wTx);
  }).then(async () => {
    const stixDomain = await loadById(stixDomainEntityId);
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomain, user);
  });
};
