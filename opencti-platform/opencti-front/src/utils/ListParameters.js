import { mergeLeft, dissoc } from 'ramda';

export const saveViewParameters = (history, location, localStorageKey, params) => {
  const localStorageParams = dissoc('searchTerm', params);
  localStorage.setItem(localStorageKey, JSON.stringify(localStorageParams));
  const urlParams = dissoc('view', params);
  history.replace(
    `${location.pathname}?${new URLSearchParams(urlParams).toString()}`,
  );
  return params;
};

export const buildViewParamsFromUrlAndStorage = (history, location, localStorageKey) => {
  const queryParams = Object.fromEntries(
    new URLSearchParams(location.search.substring(1)),
  );
  let finalParams = queryParams;
  if (localStorage.getItem(localStorageKey)) {
    const localParams = JSON.parse(localStorage.getItem(localStorageKey));
    finalParams = mergeLeft(queryParams, localParams);
  }
  if (finalParams.orderAsc === 'true') {
    finalParams.orderAsc = true;
  }
  saveViewParameters(history, location, localStorageKey, finalParams);
  return finalParams;
};
