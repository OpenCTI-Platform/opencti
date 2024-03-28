const setStackDataInSessionStorage = (key: string, valueToStore: unknown, stackValue: number): void => {
  const storedStackData = sessionStorage.getItem(key);
  const currentStoredStackData = storedStackData ? JSON.parse(storedStackData) : [];

  currentStoredStackData.unshift(valueToStore);

  const newStackDataToStore = currentStoredStackData.slice(0, stackValue);

  sessionStorage.setItem(key, JSON.stringify(newStackDataToStore));
};

export default setStackDataInSessionStorage;
