import { mergeLeft } from 'ramda';

export const saveParams = (history, location, localStorageKey, params) => {
  localStorage.setItem(localStorageKey, JSON.stringify(params));
  history.push(`${location.pathname}?${new URLSearchParams(params).toString()}`);
  return params;
};

export const getParams = (history, location, localStorageKey) => {
  const queryParams = Object.fromEntries(
    new URLSearchParams(location.search.substring(1)),
  );
  let finalParams = queryParams;
  if (finalParams.orderAsc === 'true') {
    finalParams.orderAsc = true;
  }
  if (localStorage.getItem(localStorageKey)) {
    const localParams = JSON.parse(localStorage.getItem(localStorageKey));
    finalParams = mergeLeft(queryParams, localParams);
  }
  saveParams(history, location, localStorageKey, finalParams);
  return finalParams;
};
