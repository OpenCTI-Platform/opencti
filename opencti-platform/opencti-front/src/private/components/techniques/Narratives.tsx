import React, { FunctionComponent } from 'react';
import { NarrativeWithSubnarrativeLineDummy } from '@components/techniques/narratives/NarrativeWithSubnarrativeLine';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import FiligranIcon from '@components/common/FiligranIcon';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { NarrativesLines_data$data } from '@components/techniques/narratives/__generated__/NarrativesLines_data.graphql';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { narrativeLineFragment } from './narratives/NarrativeLine';
import { narrativesLinesFragment, narrativesLinesQuery } from './narratives/NarrativesLines';
import NarrativesWithSubnarrativesLines from './narratives/NarrativesWithSubnarrativesLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import NarrativeCreation from './narratives/NarrativeCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from './narratives/__generated__/NarrativesLinesPaginationQuery.graphql';
import useHelper from '../../../utils/hooks/useHelper';
import SearchInput from '../../../components/SearchInput';
import ViewSwitchingButtons from '../../../components/ViewSwitchingButtons';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'narratives';

const Narratives: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['In regards of'], ['Narrative']),
    },
    view: 'lines',
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NarrativesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    searchTerm,
    filters,
    view,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Narrative', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as NarrativesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<NarrativesLinesPaginationQuery>(
    narrativesLinesQuery,
    queryPaginationOptions,
  );
  const renderSubEntityLines = () => {
    return (
      <>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: -10,
        }}
        >
          <SearchInput
            variant="small"
            onSubmit={helpers.handleSearch}
            keyword={searchTerm}
          />
          <div style={{
            marginTop: -5,
            marginRight: 35,
          }}
          >
            <ToggleButtonGroup
              size="small"
              color="secondary"
              value={view || 'lines'}
              exclusive={true}
            >
              <ViewSwitchingButtons
                handleChangeView={helpers.handleChangeView}
                disableCards={true}
                currentView={view}
                enableSubEntityLines={true}
              />
            </ToggleButtonGroup>
          </div>
        </div>
        <div className="clearfix" />
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <NarrativeWithSubnarrativeLineDummy key={idx} />
                  ))}
              </>
            }
          >
            <NarrativesWithSubnarrativesLines
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </>
    );
  };

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        percentWidth: 25,
        isSortable: true,
      },
      description: {
        label: 'Description',
        percentWidth: 25,
        isSortable: false,
      },
      objectLabel: {
        label: 'Labels',
        percentWidth: 20,
        isSortable: false,
      },
      created: {
        label: 'Original creation date',
        percentWidth: 15,
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        percentWidth: 15,
        isSortable: true,
      },
    };

    const preloadedPaginationProps = {
      linesQuery: narrativesLinesQuery,
      linesFragment: narrativesLinesFragment,
      queryRef,
      nodePath: ['narratives', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<NarrativesLinesPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            exportContext={{ entity_type: 'Narrative' }}
            lineFragment={narrativeLineFragment}
            resolvePath={(data: NarrativesLines_data$data) => data.narratives?.edges?.map(({ node }) => node)}
            preloadedPaginationProps={preloadedPaginationProps}
            toolbarFilters={contextFilters}
            additionalHeaderButtons={[
              (
                <Tooltip key={'lines'} title={t_i18n('Lines view')}>
                  <ToggleButton
                    value="lines"
                    aria-label="lines"
                  >
                    <FiligranIcon icon={ListViewIcon} color="primary" size="small" />
                  </ToggleButton>
                </Tooltip>
              ),
              (
                <Tooltip key={'subEntityLines'} title={t_i18n('Sub entity lines view')}>
                  <ToggleButton
                    value="subEntityLines"
                    aria-label="subEntityLines"
                    style={{ height: 36 }}
                  >
                    <FiligranIcon icon={SublistViewIcon} color="secondary" size="small" />
                  </ToggleButton>
                </Tooltip>
              )]}
            createButton={isFABReplaced && (
              <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
                <NarrativeCreation paginationOptions={queryPaginationOptions} />
              </Security>
            )}
          />
        )}
      </>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Narratives'), current: true }]} />
      {view === 'lines' ? renderLines() : ''}
      {view === 'subEntityLines' ? renderSubEntityLines() : ''}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
          <NarrativeCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </ExportContextProvider>
  );
};
export default Narratives;
