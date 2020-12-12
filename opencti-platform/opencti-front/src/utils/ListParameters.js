import {
  mergeLeft,
  dissoc,
  pipe,
  split,
  toPairs,
  map,
  head,
  last,
  assoc,
} from 'ramda';

export const saveViewParameters = (
  history,
  location,
  localStorageKey,
  params,
) => {
  localStorage.setItem(localStorageKey, JSON.stringify(params));
  let urlParams = pipe(
    dissoc('view'),
    dissoc('types'),
    dissoc('openExports'),
    dissoc('numberOfElements'),
    dissoc('selectedElements'),
    dissoc('lastSeenStart'),
    dissoc('lastSeenStop'),
  )(params);
  if (params.filters) {
    urlParams = assoc('filters', JSON.stringify(params.filters), urlParams);
  }
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
  ].reduce(
    (q, [k, v]) => Object.assign(q, { [k]: v === 'null' ? null : v }),
    {},
  );
  let finalParams = queryParams;
  if (localStorage.getItem(localStorageKey)) {
    const localParams = JSON.parse(localStorage.getItem(localStorageKey));
    finalParams = mergeLeft(queryParams, localParams);
  }
  if (finalParams.orderAsc) {
    finalParams.orderAsc = finalParams.orderAsc.toString() === 'true';
  }
  if (typeof finalParams.stixDomainObjectsTypes === 'string') {
    finalParams.stixDomainObjectsTypes = finalParams.stixDomainObjectsTypes
      ? (finalParams.stixDomainObjectsTypes = split(
        ',',
        finalParams.stixDomainObjectsTypes,
      ))
      : [];
  }
  if (typeof finalParams.indicatorTypes === 'string') {
    finalParams.indicatorTypes = finalParams.stixDomainObjectsTypes
      ? split(',', finalParams.indicatorTypes)
      : [];
  }
  if (typeof finalParams.observableTypes === 'string') {
    finalParams.observableTypes = finalParams.observableTypes
      ? split(',', finalParams.observableTypes)
      : '';
  }
  if (typeof finalParams.filters === 'string') {
    finalParams.filters = finalParams.filters
      ? JSON.parse(finalParams.filters)
      : {};
  }
  saveViewParameters(history, location, localStorageKey, finalParams);
  return finalParams;
};

export const convertFilters = (filters) => pipe(
  toPairs,
  map((pair) => {
    let key = head(pair);
    let operator = 'eq';
    if (key.endsWith('start_date') || key.endsWith('_gt')) {
      key = key.replace('_start_date', '').replace('_gt', '');
      operator = 'gt';
    } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
      key = key.replace('_end_date', '').replace('_lt', '');
      operator = 'lt';
    }
    const values = last(pair);
    const valIds = map((v) => v.id, values);
    return { key, values: valIds, operator };
  }),
)(filters);
