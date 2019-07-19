import {
  escapeString,
  queryAttributeValues,
  queryAttributeValueById,
  deleteAttributeById,
  takeWriteTx,
  commitWriteTx,
  closeWriteTx,
  getByGraknId,
  getAttributes
} from '../database/grakn';
import { logger } from '../config/conf';
import { index } from '../database/elasticSearch';

export const findById = attributeId => {
  return queryAttributeValueById(attributeId);
};

export const findAll = args => {
  return queryAttributeValues(args.type);
};

export const addAttribute = async attribute => {
  const wTx = await takeWriteTx();
  try {
    const query = `insert $attribute isa ${
      attribute.type
    }; $attribute "${escapeString(attribute.value)}";`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const attributeIterator = await wTx.tx.query(query);
    const createdAttribute = await attributeIterator.next();
    const createdAttributeId = await createdAttribute.map().get('attribute').id;
    await commitWriteTx(wTx);
    return {
      id: createdAttributeId,
      type: attribute.type,
      value: attribute.value
    };
  } catch (err) {
    logger.error(err);
    await closeWriteTx(wTx);
    return Promise.resolve({});
  }
};

export const attributeDelete = async id => {
  return deleteAttributeById(id);
};

export const attributeUpdate = async (id, input) => {
  const wTx = await takeWriteTx();
  try {
    // Add the new attribute
    const newAttribute = await addAttribute({
      type: input.type,
      value: input.newValue
    });

    // Replace all attributes
    const query = `match $e isa entity, has ${escape(
      input.type
    )} $a; $a "${escapeString(input.value)}"; insert $e has ${escape(
      input.type
    )} $attribute; $attribute "${escapeString(input.newValue)}";`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const iterator = await wTx.tx.query(query);
    const answers = await iterator.collect();
    const entitiesIndexPromise = Promise.all(
      answers.map(async answer => {
        const entity = answer.map().get('e');
        const entityAttributes = await getAttributes(entity, true);
        if (entityAttributes.entity_type === 'stix_relation') {
          return index('stix-relations', 'stix_relation', entityAttributes);
        }
        if (
          entityAttributes.parent_type === 'Stix-Domain-Entity' ||
          entityAttributes.parent_type === 'Identity'
        ) {
          return index(
            'stix-domain-entities',
            'stix_domain_entity',
            entityAttributes
          );
        }
        return null;
      })
    );
    await Promise.resolve(entitiesIndexPromise);

    await commitWriteTx(wTx);

    // Delete old attribute
    await deleteAttributeById(id);

    // Return the new attribute
    return Promise.resolve(newAttribute);
  } catch (err) {
    logger.error(err);
    await closeWriteTx(wTx);
    return Promise.resolve({});
  }
};
