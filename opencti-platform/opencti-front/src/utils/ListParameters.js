import {
  mergeLeft, dissoc, pipe, split,
} from 'ramda';

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
    dissoc('openExports'),
    dissoc('numberOfElements'),
    dissoc('selectedElements'),
    dissoc('lastSeenStart'),
    dissoc('lastSeenStop'),
    dissoc('inferred'),
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
  if (typeof finalParams.stixDomainEntitiesTypes === 'string') {
    finalParams.stixDomainEntitiesTypes = finalParams.stixDomainEntitiesTypes
      ? (finalParams.stixDomainEntitiesTypes = split(
        ',',
        finalParams.stixDomainEntitiesTypes,
      ))
      : [];
  }
  if (typeof finalParams.indicatorTypes === 'string') {
    finalParams.indicatorTypes = finalParams.stixDomainEntitiesTypes
      ? split(',', finalParams.indicatorTypes)
      : [];
  }
  if (typeof finalParams.observableTypes === 'string') {
    finalParams.observableTypes = finalParams.observableTypes
      ? split(',', finalParams.observableTypes)
      : '';
  }
  saveViewParameters(history, location, localStorageKey, finalParams);
  return finalParams;
};
