import {
  deleteAttributeById,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  queryAttributes,
  reindexAttributeValue,
} from '../database/grakn';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
} from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';

export const findById = (attributeId) => queryAttributeValueByGraknId(attributeId);

export const findAll = (args) => {
  if (args.elementType) {
    return queryAttributes(args.elementType);
  }
  return queryAttributeValues(args.type);
};

export const addAttribute = async () => {
  // return executeWrite(async (wTx) => {
  //   const query = `insert $attribute isa ${attribute.type}; $attribute "${escapeString(attribute.value)}";`;
  //   logger.debug(`[GRAKN - infer: false] addAttribute`, { query });
  //   const attributeIterator = await wTx.query(query);
  //   const createdAttribute = await attributeIterator.next();
  //   const createdAttributeId = await createdAttribute.map().get('attribute').id;
  //   return {
  //     id: createdAttributeId,
  //     type: attribute.type,
  //     value: attribute.value,
  //   };
  // });
  // TODO JRI MIGRATION
};

export const attributeDelete = async (id) => {
  return deleteAttributeById(id);
};

export const attributeUpdate = async (id, input) => {
  // Add the new attribute
  const newAttribute = await addAttribute({
    type: input.type,
    value: input.newValue,
  });
  // Link new attribute to every entities
  // TODO JRI MIGRATION
  // await executeWrite(async (wTx) => {
  //   const writeQuery = `match $e isa entity, has ${escape(input.type)} $a; $a "${escapeString(
  //     input.value
  //   )}"; insert $e has ${escape(input.type)} $attribute; $attribute "${escapeString(input.newValue)}";`;
  //   logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: writeQuery });
  //   await wTx.query(writeQuery);
  // });
  // // Link new attribute to every relations
  // await executeWrite(async (wTx) => {
  //   const writeQuery = `match $e isa relation, has ${escape(input.type)} $a; $a "${escapeString(
  //     input.value
  //   )}"; insert $e has ${escape(input.type)} $attribute; $attribute "${escapeString(input.newValue)}";`;
  //   logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: writeQuery });
  //   await wTx.query(writeQuery);
  // });
  // Delete old attribute
  await deleteAttributeById(id);
  // Reindex all entities using this attribute
  await reindexAttributeValue(ABSTRACT_STIX_DOMAIN_OBJECT, input.type, input.newValue);
  await reindexAttributeValue(ABSTRACT_STIX_CYBER_OBSERVABLE, input.type, input.newValue);
  await reindexAttributeValue(ABSTRACT_STIX_CORE_RELATIONSHIP, input.type, input.newValue);
  await reindexAttributeValue(STIX_SIGHTING_RELATIONSHIP, input.type, input.newValue);
  // Return the new attribute
  return newAttribute;
};
