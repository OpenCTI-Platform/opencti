/**
 * Set data in Session storage.
 * Data is stringified automatically.
 *
 * @param key Key in Session storage.
 * @param item Data to save.
 */
export function setSessionStorageItem<T>(key: string, item: T) {
  sessionStorage.setItem(key, JSON.stringify(item));
}

/**
 * Get data from Session storage.
 * Data is parsed automatically.
 *
 * @param key Key in Session storage.
 * @returns Data from Session storage.
 */
export function getSessionStorageItem<T>(key: string): T | null {
  const data = sessionStorage.getItem(key);
  return data ? JSON.parse(data) : null;
}

/**
 * Add a new entry in a stack saved in Session storage.
 *
 * @param key The key in Session storage
 * @param valueToStore What to add in the stack.
 * @param stackSize The max size of the stack.
 */
export function addInSessionStorageStack<T>(
  key: string,
  valueToStore: T,
  stackSize: number,
): void {
  const storedStackData = sessionStorage.getItem(key) ?? '[]';
  const currentStoredStackData = JSON.parse(storedStackData) as T[];
  // Add the current state at the beginning of the array.
  currentStoredStackData.unshift(valueToStore);
  // Remove the exceeding part if any.
  const newStackDataToStore = currentStoredStackData.slice(0, stackSize);
  // Save the new state of the stack
  setSessionStorageItem(key, newStackDataToStore);
}
