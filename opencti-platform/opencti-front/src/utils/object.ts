/**
 * Get the value of a property of an object.
 * Examples of path : objectLabel.value, representative.main, created_at...
 *
 * @param object The object to manipulate.
 * @param path The path to access the property.
 * @returns The value of the property.
 */
function getObjectProperty<T extends object>(object: T, path = ''): unknown {
  const splitPath = path.split('.');
  const property = object[splitPath.shift() as keyof T];

  // If at the end of the path, stop recursion.
  if (splitPath.length === 0) return property;
  // If not at the end of the path but the value is not an object, throw error.
  if (typeof property !== 'object' || property === null) throw Error(`Invalid path "${path}", a subpart is not an object`);
  // Continue deeper, if it's array then need to continue for each element of the array.
  return Array.isArray(property)
    ? property.map((el) => getObjectProperty(el, splitPath.join('.')))
    : getObjectProperty(property, splitPath.join('.'));
}

export default getObjectProperty;
