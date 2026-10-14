import { fromB64, toB64 } from './String';

type GetObjectPropertyOptions = {
  // Resolve to undefined instead of throwing when a subpart of the path is null or undefined.
  nullableSubparts?: boolean;
};

/**
 * Get the value of a property of an object.
 * Examples of path : objectLabel.value, representative.main, created_at...
 *
 * @param object The object to manipulate.
 * @param path The path to access the property.
 * @param options Lookup options.
 * @returns The value of the property.
 */
export function getObjectProperty<T extends object>(object: T, path = '', options?: GetObjectPropertyOptions): unknown {
  const splitPath = path.split('.');
  const property = object[splitPath.shift() as keyof T];

  // If at the end of the path, stop recursion.
  if (splitPath.length === 0) return property;
  // If not at the end of the path but the value is missing, the whole property is missing.
  if (options?.nullableSubparts && (property === null || property === undefined)) return undefined;
  // If not at the end of the path but the value is not an object, throw error.
  if (typeof property !== 'object' || property === null) throw Error(`Invalid path "${path}", a subpart is not an object`);
  // Continue deeper, if it's array then need to continue for each element of the array.
  return Array.isArray(property)
    ? property.map((el) => (options?.nullableSubparts && (el === null || el === undefined)
      ? undefined
      : getObjectProperty(el, splitPath.join('.'), options)))
    : getObjectProperty(property, splitPath.join('.'), options);
}

/**
 * Same as getObjectProperty but
 * - return '' if the value is null/undefined
 * - remove the null/undefined values from the array if the result is an array
 *
 * @param object The object to manipulate.
 * @param path The path to access the property.
 * @param options Lookup options.
 * @returns The value of the property.
 */
export function getObjectPropertyWithoutEmptyValues<T extends object>(object: T, path = '', options?: GetObjectPropertyOptions): unknown {
  const property = getObjectProperty(object, path, options);
  if (Array.isArray(property)) {
    return property.filter((p) => !!p);
  }
  return property ?? '';
}

export const isEmptyObject = (o: object) => Object.keys(o).length === 0;

export const serializeObjectB64 = (o: object) => toB64(JSON.stringify(o));

export const deserializeObjectB64 = (data: string | null | undefined) => {
  if (data) {
    const decodedData = JSON.parse(fromB64(data));
    if (typeof decodedData === 'object') {
      return decodedData;
    }
  }
  return {};
};
