import {
  dissoc,
  mergeLeft,
  pipe,
  split,
} from 'ramda';
import { APP_BASE_PATH } from '../relay/environment';
import { initialFilterGroup } from './filters/filtersUtils';

const buildParamsFromHistory = (params) => {
  let urlParams = pipe(
    dissoc('graphData'),
    dissoc('openTimeField'),
    dissoc('anchorEl'),
    dissoc('view'),
    dissoc('types'),
    dissoc('openExports'),
    dissoc('numberOfElements'),
    dissoc('selectedElements'),
    dissoc('selectAll'),
    dissoc('numberOfSelectedElements'),
    dissoc('numberOfSelectedNodes'),
    dissoc('numberOfSelectedLinks'),
    dissoc('lastSeenStart'),
    dissoc('lastSeenStop'),
    dissoc('initialContent'),
    dissoc('currentContent'),
    dissoc('currentHtmlContent'),
    dissoc('currentBase64Content'),
    dissoc('totalPdfPageNumber'),
    dissoc('currentPdfPageNumber'),
    dissoc('mentions'),
    dissoc('mentionKeyword'),
    dissoc('allCreatedBy'),
    dissoc('allMarkedBy'),
    dissoc('allStixCoreObjectsTypes'),
    dissoc('rectSelected'),
    dissoc('navOpen'),
  )(params);
  if (params.filters) {
    urlParams = {
      ...urlParams,
      filters: JSON.stringify(params.filters),
    };
  }
  if (params.timeLineFilters) {
    urlParams = {
      ...urlParams,
      timeLineFilters: JSON.stringify(params.timeLineFilters),
    };
  }
  if (params.zoom) {
    urlParams = {
      ...urlParams,
      zoom: JSON.stringify(params.zoom),
    };
  }
  return new URLSearchParams(urlParams).toString();
};

const saveParamsToLocalStorage = (localStorageKey, params) => {
  const storageParams = pipe(
    dissoc('timeLineSearchTerm'),
    dissoc('graphData'),
    dissoc('anchorEl'),
    dissoc('openTimeField'),
    dissoc('initialContent'),
    dissoc('currentContent'),
    dissoc('currentHtmlContent'),
    dissoc('currentBase64Content'),
    dissoc('totalPdfPageNumber'),
    dissoc('currentPdfPageNumber'),
    dissoc('mentions'),
    dissoc('mentionKeyword'),
    dissoc('allCreatedBy'),
    dissoc('allMarkedBy'),
    dissoc('allStixCoreObjectsTypes'),
    dissoc('rectSelected'),
    dissoc('navOpen'),
  )(params);
  localStorage.setItem(localStorageKey, JSON.stringify(storageParams));
};

export const saveViewParameters = (
  history,
  location,
  localStorageKey,
  params,
  refresh = false,
) => {
  // Save the params in local storage
  saveParamsToLocalStorage(localStorageKey, params);
  // Apply params in history
  const searchParams = buildParamsFromHistory(params);
  const newUrl = `${APP_BASE_PATH}${location.pathname}?${searchParams}`;
  if (refresh) {
    history.replace(newUrl);
  } else {
    window.history.replaceState(null, '', newUrl);
  }
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
  if (finalParams.modeFixed) {
    finalParams.modeFixed = finalParams.modeFixed.toString() === 'true';
  }
  if (finalParams.nestedRelationships) {
    finalParams.nestedRelationships = finalParams.nestedRelationships.toString() === 'true';
  }
  if (finalParams.timeLineDisplayRelationships) {
    finalParams.timeLineDisplayRelationships = finalParams.timeLineDisplayRelationships.toString() === 'true';
  }
  if (finalParams.timeLineFunctionalDate) {
    finalParams.timeLineFunctionalDate = finalParams.timeLineFunctionalDate.toString() === 'true';
  }
  if (finalParams.currentTab) {
    finalParams.currentTab = parseInt(finalParams.currentTab, 10);
  }
  if (finalParams.pdfViewerZoom) {
    finalParams.pdfViewerZoom = parseFloat(finalParams.pdfViewerZoom);
  }
  if (finalParams.currentModeOnlyActive) {
    finalParams.currentModeOnlyActive = finalParams.currentModeOnlyActive.toString() === 'true';
  }
  if (finalParams.currentColorsReversed) {
    finalParams.currentColorsReversed = finalParams.currentColorsReversed.toString() === 'true';
  }
  if (finalParams.selectRectangleModeFree) {
    finalParams.selectRectangleModeFree = finalParams.selectRectangleModeFree.toString() === 'true';
  }
  if (finalParams.selectModeFree) {
    finalParams.selectModeFree = finalParams.selectModeFree.toString() === 'true';
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
  if (typeof finalParams.timeLineFilters === 'string') {
    finalParams.timeLineFilters = finalParams.timeLineFilters
      ? JSON.parse(finalParams.timeLineFilters)
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
