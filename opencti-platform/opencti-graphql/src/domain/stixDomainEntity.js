import { dissoc, map } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  loadEntityById,
  loadEntityByStixId,
  paginate,
  timeSeries,
  updateAttribute
} from '../database/grakn';
import { elCount, elFindTermsOr, elPaginate, INDEX_STIX_ENTITIES } from '../database/elasticSearch';

import { generateFileExportName, upload } from '../database/minio';
import { connectorsForExport } from './connector';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';

// region elastic fetch
export const findAll = args => elPaginate('stix_domain_entities', args);
export const findById = stixDomainEntityId => loadEntityById(stixDomainEntityId);
export const findByStixId = args => loadEntityByStixId(args.stix_id_key);
export const findByName = args => {
  // return paginate(
  //   `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
  //  $x has name $name;
  //  $x has alias $alias;
  //  { $name "${escapeString(args.name)}"; } or
  //  { $alias "${escapeString(args.name)}"; }`,
  //   args,
  //   false
  // );
  return elFindTermsOr(
    [{ 'name.keyword': escapeString(args.name) }, { 'alias.keyword': escapeString(args.name) }],
    [INDEX_STIX_ENTITIES]
  );
};
export const stixDomainEntitiesNumber = args => ({
  count: elCount('stix_domain_entities', args),
  total: elCount('stix_domain_entities', dissoc('endDate', args))
});
// endregion

// region grakn fetch
export const stixDomainEntitiesTimeSeries = args => {
  return timeSeries(`match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'}`, args);
};
export const findByExternalReference = args => {
  return paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
     $rel(external_reference:$externalReference, so:$x) isa external_references;
     $externalReference has internal_id_key "${escapeString(args.externalReferenceId)}"`,
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
// endregion

const askJobExports = async (entity, format, exportType) => {
  const connectors = await connectorsForExport(format, true);
  // Create job for every connectors
  const workList = await Promise.all(
    map(connector => {
      const fileName = generateFileExportName(format, connector, exportType, entity);
      return createWork(connector, entity.id, fileName).then(({ work, job }) => ({
        connector,
        job,
        work
      }));
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
export const stixDomainEntityExportAsk = async (domainEntityId, format, exportType) => {
  const entity = await loadEntityById(domainEntityId);
  const workList = await askJobExports(entity, format, exportType);
  // Return the work list to do
  return map(w => workToExportFile(w.work), workList);
};

// region mutation
export const stixDomainEntityExportPush = async (user, entityId, file) => {
  // Upload the document in minio
  await upload(user, 'export', file, entityId);
  return true;
};
export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const innerType = stixDomainEntity.type;
  const domainToCreate = dissoc('type', stixDomainEntity);
  const created = await createEntity(domainToCreate, innerType);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const stixDomainEntityDelete = async stixDomainEntityId => {
  return deleteEntityById(stixDomainEntityId);
};
export const stixDomainEntityAddRelation = (user, stixDomainEntityId, input) => {
  return createRelation(stixDomainEntityId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixDomainEntityAddRelations = async (user, stixDomainEntityId, input) => {
  const finalInput = map(
    n => ({
      toId: n,
      fromRole: input.fromRole,
      toRole: input.toRole,
      through: input.through
    }),
    input.toIds
  );
  await createRelations(stixDomainEntityId, finalInput);
  return loadEntityById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, stixDomainEntity, user)
  );
};
export const stixDomainEntityDeleteRelation = (user, stixDomainEntityId, relationId) => {
  return deleteRelationById(stixDomainEntityId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixDomainEntityEditField = async (user, stixDomainEntityId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(stixDomainEntityId, input, wTx);
  }).then(async () => {
    const stixDomain = await loadEntityById(stixDomainEntityId);
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomain, user);
  });
};
// endregion

// region context
export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return loadEntityById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};
export const stixDomainEntityEditContext = (user, stixDomainEntityId, input) => {
  setEditContext(user, stixDomainEntityId, input);
  return loadEntityById(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};
// endregion
