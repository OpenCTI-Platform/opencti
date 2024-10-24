/**
 * Get the value of a property of an object.
 *
 * @param object The object to manipulate.
 * @param path The path to access the property.
 * @returns The value of the property.
 */
export function getObjectProperty(object: object, path = ''): unknown {
  return path.split('.').reduce(
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    (o, x) => (o === undefined ? o : o[x]),
    object,
  );
}

export const fetchAttributeFromData = (object: unknown, splittedAttribute: string[]): unknown => {
  if (splittedAttribute.length === 1) {
    return object?.[splittedAttribute[0]];
  }
  const subObject = object?.[splittedAttribute[0]];
  return Array.isArray(subObject)
    ? subObject.map((o) => fetchAttributeFromData(o, splittedAttribute.slice(1)))
    : fetchAttributeFromData(subObject, splittedAttribute.slice(1));
};
