/**
 * Mutation resolvers for threat actors.
 */
import { logApp } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elUpdate } from '../database/engine';
import { storeLoadByIdWithRefs } from '../database/middleware';
import { storeLoadById } from '../database/middleware-loader';
import type { HeightTupleInput, HeightTupleInputValues, InputMaybe, WeightTupleInputValues } from '../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';

const type = ABSTRACT_STIX_DOMAIN_OBJECT;

enum HeightOrWeight {
  HEIGHT = 'height',
  WEIGHT = 'weight',
}

interface DocParams {
  internal_id: string,
  height?: any,
  weight?: any,
}

/**
 * Attempts to update a record.
 *
 * @param context System context.
 * @param user User calling this mutation.
 * @param index Which index the record is in.
 * @param id Internal ID of the record to mutate.
 * @param source Mutation script source.
 * @param params Parameters passed to the mutation.
 * @returns Updated record or error.
 */
const updateRecord = async (context: AuthContext, user: AuthUser, index: string, id: string, source: string, params: DocParams) => {
  try {
    await elUpdate(index, id, {
      script: { source, params },
    });
    return await storeLoadByIdWithRefs(context, user, id, { type });
  } catch (error) {
    logApp.error('Failed to update threatActor record', { error });
    return { error: 'Failed to update record.', id };
  }
};

const removeEmptyHeightTuples = (values: HeightTupleInputValues[]) => {
  if (!Array.isArray(values) || values.length < 1) return [];
  return values.filter(({ height_in, height_cm }) => height_in || height_cm);
};

const removeEmptyWeightTuples = (values: WeightTupleInputValues[]) => {
  if (!Array.isArray(values) || values.length < 1) return [];
  return values.filter(({ weight_lb, weight_kg }) => weight_lb || weight_kg);
};

/**
 * Sorts a list of objects with field date_seen.
 * Entries with null or undefined date_seen float to the top, followed by
 * the most recent entries.
 * Removes entries without a height/weight value.
 *
 * @param values List of objects with date_seen field.
 * @returns Sorted values.
 */
const sortByDateSeen = (
  values: InputMaybe<InputMaybe<HeightTupleInputValues>[]>
  | InputMaybe<InputMaybe<WeightTupleInputValues>[]>
  | undefined,
  key: string,
): InputMaybe<InputMaybe<HeightTupleInputValues>[]> | undefined => {
  const finalValues = key === 'height'
    ? removeEmptyHeightTuples(values as HeightTupleInputValues[])
    : removeEmptyWeightTuples(values as WeightTupleInputValues[]);
  return finalValues.sort((leftValue, rightValue) => {
    const leftDate = Date.parse(leftValue?.date_seen);
    const rightDate = Date.parse(rightValue?.date_seen);
    if (Number.isNaN(leftDate)) return -1;
    if (Number.isNaN(rightDate)) return 1;
    return leftDate < rightDate ? -1 : 1;
  });
};

/**
 * Helper function for _roundAndConvert with height tuples.
 *
 * @param values List of height tuples to be rounded and converted.
 * @returns Rounded and converted height tuples.
 */
const _roundAndConvertHeight = (values: HeightTupleInputValues[]) => {
  const inToCm = (inches: number) => inches * 2.54;
  const cmToIn = (cm: number) => cm / 2.54;
  const convertedValues: HeightTupleInputValues[] = [];

  values.forEach(({ height_in, height_cm, date_seen }) => {
    if (
      height_in
      && Math.round(height_cm ?? -1) !== Math.round(inToCm(height_in))
    ) {
      convertedValues.push({
        height_in,
        height_cm: inToCm(height_in),
        date_seen,
      });
    } else if (
      height_cm
      && Math.round(height_in ?? -1) !== Math.round(cmToIn(height_cm))
    ) {
      convertedValues.push({
        height_cm,
        height_in: cmToIn(height_cm),
        date_seen,
      });
    } else {
      convertedValues.push({ height_in, height_cm, date_seen });
    }
  });

  return convertedValues;
};

/**
 * Helper function for _roundAndConvert with weight tuples.
 *
 * @param values List of weight tuples to be rounded and converted.
 * @returns Rounded and converted weight tuples.
 */
const _roundAndConvertWeight = (values: WeightTupleInputValues[]) => {
  const lbToKg = (lb: number) => lb * 0.453592;
  const kgToLb = (kg: number) => kg / 0.453592;
  const convertedValues: WeightTupleInputValues[] = [];

  values.forEach(({ weight_lb, weight_kg, date_seen }) => {
    if (
      weight_lb
      && Math.round(weight_kg ?? -1) !== Math.round(lbToKg(weight_lb))
    ) {
      convertedValues.push({
        weight_lb,
        weight_kg: lbToKg(weight_lb),
        date_seen,
      });
    } else if (
      weight_kg
      && Math.round(weight_lb ?? -1) !== Math.round(kgToLb(weight_kg))
    ) {
      convertedValues.push({
        weight_kg,
        weight_lb: kgToLb(weight_kg),
        date_seen,
      });
    } else {
      convertedValues.push({ weight_lb, weight_kg, date_seen });
    }
  });

  return convertedValues;
};

/**
 * Given an incomplete or incorrect pair of units, converts and corrects
 * the units.
 * e.g. Given height_in and no height_cm, this will return the appropriate
 *  values for both.
 * e.g. Given weight_lb and incorrect weight_kg conversion, this will
 *  convert weight_lb to the correct weight_kg.
 * This function favors imperial measurements over metric. This means that
 * if it is given two values that do not convert to one another, this
 * function uses the imperial measurement to override the metric one.
 *
 * @param key
 * @param values
 * @returns List of values to add.
 */
const _roundAndConvert = (key: HeightOrWeight, values: InputMaybe<InputMaybe<HeightTupleInputValues>[]> | InputMaybe<InputMaybe<WeightTupleInputValues>[]> | undefined) => {
  if (values && Array.isArray(values)) {
    return key === HeightOrWeight.HEIGHT
      ? _roundAndConvertHeight(values as HeightTupleInputValues[])
      : _roundAndConvertWeight(values as WeightTupleInputValues[]);
  } return [];
};

/**
 * Common helper code for height and weight mutations.
 *
 * @param context System context.
 * @param user User calling this mutation.
 * @param id Internal ID of the record to mutate.
 * @param input Requested mutation.
 * @param key Either "height" or "weight".
 * @param sort Whether to sort the updated values or not. Defaults to true.
 * @returns Updated record or an error.
 */
const heightWeightEdit = async (context: AuthContext, user: AuthUser, id: string, input: HeightTupleInput, key: HeightOrWeight, sort: boolean = true) => {
  const stixDomainObject = await storeLoadById(context, user, id, type);
  const doc: DocParams = { internal_id: id };
  const initial = await storeLoadByIdWithRefs(context, user, id, { type });
  if (!initial) {
    throw FunctionalError("Can't find element to update", { id, type });
  }

  // Get initial values
  const initialValues = key in initial && Array.isArray(initial[key]) ? initial[key] : [];

  // Push new value(s)
  const { operation = 'add', values } = { ...input };
  const index = input?.index as number ?? -1;
  const convertedValues = _roundAndConvert(key, values);

  // Create the final values to send to the DB
  let finalValues;
  switch (operation) {
    case 'replace':
      if (
        index >= 0
        && key in initial
        && initial[key].length > index
        && values?.length === 1
      ) {
        // replace a single entry at the specified index
        finalValues = initialValues;
        const [convertedValue] = convertedValues;
        finalValues[index] = convertedValue;
      } else {
        // replace the whole list
        finalValues = convertedValues;
      }
      break;
    case 'remove':
      if (index >= 0 && key in initial && initial[key].length > index) {
        // remove a single entry at the specified index
        finalValues = initialValues;
        finalValues.splice(index, 1);
      } // else remove the whole list (no-op)
      break;
    default: // add
      // add newValues to initialValues
      finalValues = initialValues.concat(convertedValues);
  }

  // sort values and replace existing list in elasticsearch
  if (sort) finalValues = sortByDateSeen(finalValues, key);
  const source = `ctx._source['${key}'] = params['${key}']`;
  if (key === 'height') {
    doc.height = finalValues;
  } else {
    doc.weight = finalValues;
  }
  return updateRecord(context, user, stixDomainObject._index, id, source, doc);
};

/**
 * Public-facing function to sort a record's height and weight attributes.
 *
 * @param context System context.
 * @param user User calling this mutation.
 * @param id Internal ID of the record to mutate.
 * @returns Updated record.
 */
export const heightWeightSort = async (context: AuthContext, user: AuthUser, id: string) => {
  const stixDomainObject = await storeLoadById(context, user, id, type);
  const doc: DocParams = { internal_id: id };
  const height_key = 'height';
  const weight_key = 'weight';
  const initial = await storeLoadByIdWithRefs(context, user, id, { type });
  if (!initial) {
    throw FunctionalError("Can't find element to update", { id, type });
  }
  const heights = height_key in initial && Array.isArray(initial[height_key])
    ? sortByDateSeen(initial[height_key], height_key)
    : [];
  const weights = weight_key in initial && Array.isArray(initial[weight_key])
    ? sortByDateSeen(initial[weight_key], weight_key)
    : [];
  doc[height_key] = heights;
  doc[weight_key] = weights;
  const source = `
    ctx._source['${height_key}'] = params['${height_key}'];
    ctx._source['${weight_key}'] = params['${weight_key}']`;
  return updateRecord(context, user, stixDomainObject._index, id, source, doc);
};

/**
 * Mutation resolver for height attribute.
 *
 * @param context System context.
 * @param user User calling this mutation.
 * @param id Internal ID of the record to mutate.
 * @param input Requested mutation.
 * @param sort Whether to sort or not. Defaults to true.
 * @returns Updated record.
 */
export const heightEdit = async (context: AuthContext, user: AuthUser, id: string, input: HeightTupleInput, sort = true) => {
  return heightWeightEdit(
    context,
    user,
    id,
    input,
    HeightOrWeight.HEIGHT,
    sort
  );
};

/**
 * Mutation resolver for weight attribute.
 *
 * @param context System context.
 * @param user User calling this mutation.
 * @param id Internal ID of the record to mutate.
 * @param input Requested mutation.
 * @param sort Whether to sort or not. Defaults to true.
 * @returns Updated record.
 */
export const weightEdit = async (context: AuthContext, user: AuthUser, id: string, input: HeightTupleInput, sort = true) => {
  return heightWeightEdit(
    context,
    user,
    id,
    input,
    HeightOrWeight.WEIGHT,
    sort
  );
};
