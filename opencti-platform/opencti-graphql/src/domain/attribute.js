import {
  escapeString,
  queryAttributeValues,
  takeWriteTx,
  commitWriteTx,
  closeWriteTx
} from '../database/grakn';
import { logger } from '../config/conf';

export const findAll = args => {
  return queryAttributeValues(args.type);
};

export const addAttribute = async (user, attribute) => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(
      `insert $attribute isa ${attribute.type}; $attribute "${escapeString(
        attribute.value
      )}"`
    );
    await commitWriteTx(wTx);
    return {
      type: attribute.type,
      value: attribute.value
    };
  } catch (err) {
    logger.error(err);
    await closeWriteTx(wTx);
    return {};
  }
};

export const attributeDelete = async (type, value) => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(
      `match $x "${escapeString(value)}" isa ${escape(type)}; delete $x;`
    );
    await commitWriteTx(wTx);
    return {
      type,
      value
    };
  } catch (err) {
    logger.error(err);
    await closeWriteTx(wTx);
    return {};
  }
};

export const attributeUpdate = async (type, value, newValue) => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(
      `match $e isa entity, has ${escape(type)} $a; $a "${escapeString(
        value
      )}"; insert $e has ${escape(type)} "${escapeString(newValue)}";`
    );
    await wTx.tx.query(
      `match $x "${escapeString(value)}" isa ${escape(type)}; delete $x;`
    );
    await commitWriteTx(wTx);
    return {
      type,
      value: newValue
    };
  } catch (err) {
    logger.error(err);
    await closeWriteTx(wTx);
    return {};
  }
};
