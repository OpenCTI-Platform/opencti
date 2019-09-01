import { mergeLeft, dissoc } from 'ramda';

export const saveViewParameters = (
  history,
  location,
  localStorageKey,
  params,
) => {
  localStorage.setItem(localStorageKey, JSON.stringify(params));
  const urlParams = dissoc('view', params);
  history.replace(
    `${location.pathname}?${new URLSearchParams(urlParams).toString()}`,
  );
  return params;
};

export const buildViewParamsFromUrlAndStorage = (
  history,
  location,
  localStorageKey,
) => {
  const queryParams = Object.fromEntries(
    new URLSearchParams(location.search.substring(1)),
  );
  let finalParams = queryParams;
  if (localStorage.getItem(localStorageKey)) {
    const localParams = JSON.parse(localStorage.getItem(localStorageKey));
    finalParams = mergeLeft(queryParams, localParams);
  }
  if (finalParams.orderAsc === 'true' || finalParams.orderAsc === true) {
    finalParams.orderAsc = true;
  } else if (
    finalParams.orderAsc === 'false'
    || finalParams.orderAsc === false
  ) {
    finalParams.orderAsc = false;
  }
  saveViewParameters(history, location, localStorageKey, finalParams);
  return finalParams;
};
