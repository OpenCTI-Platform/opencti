type SetDataOnSessionStorageParams = {
  valueToStore: unknown;
  key: string;
  stackValue: number;
};
const setStackDataInSessionStorage = ({ valueToStore, key, stackValue }: SetDataOnSessionStorageParams): void => {
  const storedStackData = sessionStorage.getItem(key);
  const currentStoredStackData = storedStackData ? JSON.parse(storedStackData) : [];

  currentStoredStackData.unshift(valueToStore);

  if (currentStoredStackData.length > stackValue) currentStoredStackData.pop();

  sessionStorage.setItem(key, JSON.stringify(currentStoredStackData));
};

export default setStackDataInSessionStorage;
