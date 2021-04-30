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
  noRedirect = false,
) => {
  const storageParams = pipe(dissoc('graphData'))(params);
  localStorage.setItem(localStorageKey, JSON.stringify(storageParams));
  let urlParams = pipe(
    dissoc('graphData'),
    dissoc('view'),
    dissoc('types'),
    dissoc('openExports'),
    dissoc('numberOfElements'),
    dissoc('selectedElements'),
    dissoc('selectAll'),
    dissoc('numberOfSelectedElements'),
    dissoc('lastSeenStart'),
    dissoc('lastSeenStop'),
  )(params);
  if (params.filters) {
    urlParams = assoc('filters', JSON.stringify(params.filters), urlParams);
  }
  if (params.zoom) {
    urlParams = assoc('zoom', JSON.stringify(params.zoom), urlParams);
  }
  if (!noRedirect) {
    window.history.replaceState(
      null,
      '',
      `${location.pathname}?${new URLSearchParams(urlParams).toString()}`,
    );
  }
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
  if (finalParams.mode3D) {
    finalParams.mode3D = finalParams.mode3D.toString() === 'true';
  }
  if (finalParams.modeTree) {
    finalParams.modeTree = finalParams.modeTree.toString() === 'true';
  }
  if (finalParams.modeFixed) {
    finalParams.modeFixed = finalParams.modeFixed.toString() === 'true';
  }
  if (finalParams.displayTimeRange) {
    finalParams.displayTimeRange = finalParams.displayTimeRange.toString() === 'true';
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
  if (typeof finalParams.zoom === 'string') {
    finalParams.zoom = finalParams.zoom ? JSON.parse(finalParams.zoom) : {};
  }
  if (typeof finalParams.stixCoreObjectsTypes === 'string') {
    finalParams.stixCoreObjectsTypes = finalParams.stixCoreObjectsTypes
      ? split(',', finalParams.stixCoreObjectsTypes)
      : '';
  }
  if (typeof finalParams.markedBy === 'string') {
    finalParams.markedBy = finalParams.markedBy
      ? split(',', finalParams.markedBy)
      : '';
  }
  if (typeof finalParams.createdBy === 'string') {
    finalParams.createdBy = finalParams.createdBy
      ? split(',', finalParams.createdBy)
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
    if (key.endsWith('start_date') || key.endsWith('_gt')) {
      key = key.replace('_start_date', '').replace('_gt', '');
      operator = 'gt';
    } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
      key = key.replace('_end_date', '').replace('_lt', '');
      operator = 'lt';
    } else if (key.endsWith('_lte')) {
      key = key.replace('_lte', '');
      operator = 'lte';
    }
    const values = last(pair);
    const valIds = map((v) => v.id, values);
    return { key, values: valIds, operator };
  }),
)(filters);
