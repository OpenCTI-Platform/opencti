import {
  deleteAttributeById,
  escapeString,
  executeWrite,
  queryAttributeValueByGraknId,
  queryAttributeValues,
  reindexEntityAttribute,
  reindexRelationAttribute,
} from '../database/grakn';
import { logger } from '../config/conf';

export const findById = (attributeId) => queryAttributeValueByGraknId(attributeId);

export const findAll = (args) => queryAttributeValues(args.type);

export const addAttribute = async (attribute) => {
  return executeWrite(async (wTx) => {
    const query = `insert $attribute isa ${attribute.type}; $attribute "${escapeString(attribute.value)}";`;
    logger.debug(`[GRAKN - infer: false] addAttribute`, { query });
    const attributeIterator = await wTx.tx.query(query);
    const createdAttribute = await attributeIterator.next();
    const createdAttributeId = await createdAttribute.map().get('attribute').id;
    return {
      id: createdAttributeId,
      type: attribute.type,
      value: attribute.value,
    };
  });
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
  await executeWrite(async (wTx) => {
    const writeQuery = `match $e isa entity, has ${escape(input.type)} $a; $a "${escapeString(
      input.value
    )}"; insert $e has ${escape(input.type)} $attribute; $attribute "${escapeString(input.newValue)}";`;
    logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: writeQuery });
    await wTx.tx.query(writeQuery);
  });
  // Link new attribute to every relations
  await executeWrite(async (wTx) => {
    const writeQuery = `match $e isa relation, has ${escape(input.type)} $a; $a "${escapeString(
      input.value
    )}"; insert $e has ${escape(input.type)} $attribute; $attribute "${escapeString(input.newValue)}";`;
    logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: writeQuery });
    await wTx.tx.query(writeQuery);
  });
  // Delete old attribute
  await deleteAttributeById(id);
  // Reindex all entities using this attribute
  await reindexEntityAttribute(input.type, input.newValue);
  await reindexRelationAttribute(input.type, input.newValue);
  // Return the new attribute
  return newAttribute;
};
