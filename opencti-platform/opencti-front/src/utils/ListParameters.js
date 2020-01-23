import { mergeLeft, dissoc, pipe } from 'ramda';

export const saveViewParameters = (
  history,
  location,
  localStorageKey,
  params,
) => {
  localStorage.setItem(localStorageKey, JSON.stringify(params));
  const urlParams = pipe(
    dissoc('view'),
    dissoc('types'),
    dissoc('indicatorTypes'),
    dissoc('observableTypes'),
    dissoc('openExports'),
    dissoc('numberOfElements'),
  )(params);
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
  const queryParams = [
    ...new URLSearchParams(location.search).entries(),
  ].reduce((q, [k, v]) => Object.assign(q, { [k]: v }), {});
  let finalParams = queryParams;
  if (localStorage.getItem(localStorageKey)) {
    const localParams = JSON.parse(localStorage.getItem(localStorageKey));
    finalParams = mergeLeft(queryParams, localParams);
  }
  if (finalParams.orderAsc) {
    finalParams.orderAsc = finalParams.orderAsc.toString() === 'true';
  }
  saveViewParameters(history, location, localStorageKey, finalParams);
  return finalParams;
};
