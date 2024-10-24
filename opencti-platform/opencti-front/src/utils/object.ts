/**
 * Get the value of a property of an object.
 *
 * @param object The object to manipulate.
 * @param path The path to access the property.
 * @returns The value of the property.
 */
function getObjectProperty(object: object, path = ''): unknown {
  return path.split('.').reduce(
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    (o, x) => (o === undefined ? o : o[x]),
    object,
  );
}

export default getObjectProperty;
