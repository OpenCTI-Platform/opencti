/**
 * Mutation resolvers for threat actors.
 */
import { FunctionalError } from '../config/errors';
import { storeLoadByIdWithRefs } from '../database/middleware';
import { stixDomainObjectEditField } from '../domain/stixDomainObject';
import { EditOperation, type HeightTupleInput, type HeightTupleInputValues, type InputMaybe, type WeightTupleInputValues } from '../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';

const type = ABSTRACT_STIX_DOMAIN_OBJECT;

enum HeightOrWeight {
  HEIGHT = 'height',
  WEIGHT = 'weight',
}

const removeEmptyHeightTuples = (values: HeightTupleInputValues[]) => {
  if (!Array.isArray(values) || values.length < 1) return [];
  return values.filter(({ height_cm }) => height_cm);
};

const removeEmptyWeightTuples = (values: WeightTupleInputValues[]) => {
  if (!Array.isArray(values) || values.length < 1) return [];
  return values.filter(({ weight_kg }) => weight_kg);
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
  const finalValues = key === HeightOrWeight.HEIGHT
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
  const initial = await storeLoadByIdWithRefs(context, user, id, { type });
  if (!initial) {
    throw FunctionalError("Can't find element to update", { id, type });
  }

  // Get initial values
  const initialValues = key in initial && Array.isArray(initial[key]) ? initial[key] : [];

  // Push new value(s)
  const { operation = 'add', values } = { ...input };
  const index = input?.index as number ?? -1;
  const convertedValues = values as HeightTupleInputValues[];

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

  // sort values and replace existing list
  if (sort) finalValues = sortByDateSeen(finalValues, key);

  const updatedInput = [{
    key,
    operation: EditOperation.Replace,
    value: finalValues,
  }];
  return stixDomainObjectEditField(context, user, id, updatedInput);
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
  const height_key = HeightOrWeight.HEIGHT;
  const weight_key = HeightOrWeight.WEIGHT;
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
  const updatedInputs = [
    {
      key: height_key,
      operation: EditOperation.Replace,
      value: heights,
    },
    {
      key: weight_key,
      operation: EditOperation.Replace,
      value: weights,
    },
  ];
  return stixDomainObjectEditField(context, user, id, updatedInputs);
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
