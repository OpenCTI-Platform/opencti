import {
  mergeLeft,
  dissoc,
  pipe,
  split,
  toPairs,
  map,
  head,
  last,
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

export const convertFilters = (filters) => pipe(
  toPairs,
  map((pair) => {
    let key = head(pair);
    let operator = 'eq';
    if (key.endsWith('start_date')) {
      key = key.replace('_start_date', '');
      operator = 'gt';
    } else if (key.endsWith('end_date')) {
      key = key.replace('_end_date', '');
      operator = 'lt';
    }
    const values = last(pair);
    const valIds = map((v) => v.id, values);
    return { key, values: valIds, operator };
  }),
)(filters);
