import {
  escapeString,
  queryAttributeValues,
  queryAttributeValueById,
  deleteAttributeById,
  takeWriteTx,
  commitWriteTx,
  getAttributes,
  takeReadTx,
  closeTx
} from '../database/grakn';
import { logger } from '../config/conf';

export const findById = attributeId => queryAttributeValueById(attributeId);

export const findAll = args => queryAttributeValues(args.type);

export const addAttribute = async attribute => {
  const wTx = await takeWriteTx();
  try {
    const query = `insert $attribute isa ${
      attribute.type
    }; $attribute "${escapeString(attribute.value)}";`;
    logger.debug(`[GRAKN - infer: false] addAttribute > ${query}`);
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
    await closeTx(wTx);
    logger.error('[GRAKN] addAttribute error > ', err);
    return {};
  }
};

export const attributeDelete = async id => {
  return deleteAttributeById(id);
};

export const attributeUpdate = async (id, input) => {
  // Add the new attribute
  const newAttribute = await addAttribute({
    type: input.type,
    value: input.newValue
  });
  const wTx = await takeWriteTx();
  // region Link new attribute to every entities
  try {
    const writeQuery = `match $e isa entity, has ${escape(
      input.type
    )} $a; $a "${escapeString(input.value)}"; insert $e has ${escape(
      input.type
    )} $attribute; $attribute "${escapeString(input.newValue)}";`;
    logger.debug(`[GRAKN - infer: false] attributeUpdate > ${writeQuery}`);
    await wTx.tx.query(writeQuery);
    await commitWriteTx(wTx);
  } catch (err) {
    await closeTx(wTx);
    logger.error('[GRAKN] attributeUpdate error > ', err);
  }
  // endregion

  // Delete old attribute
  await deleteAttributeById(id);

  // region Reindex all entities using this attribute
  const rTx = await takeReadTx();
  try {
    const readQuery = `match $x isa entity, has ${escape(
      input.type
    )} $a; $a "${escapeString(input.newValue)}"; get;`;
    logger.debug(`[GRAKN - infer: false] attributeUpdate > ${readQuery}`);
    const iterator = await rTx.tx.query(readQuery);
    const answers = await iterator.collect();
    await Promise.all(
      answers.map(answer => {
        const entity = answer.map().get('x');
        return getAttributes(entity, true);
      })
    );
    await closeTx(rTx);
  } catch (err) {
    await closeTx(rTx);
    logger.error('[GRAKN] attributeUpdate error > ', err);
  }
  // endregion

  // Return the new attribute
  return newAttribute;
};
