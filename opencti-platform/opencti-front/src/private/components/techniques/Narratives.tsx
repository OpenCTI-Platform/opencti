import FiligranIcon from '@components/common/FiligranIcon';
import { NarrativeWithSubnarrativeLineDummy } from '@components/techniques/narratives/NarrativeWithSubnarrativeLine';
import { NarrativesLines_data$data } from '@components/techniques/narratives/__generated__/NarrativesLines_data.graphql';
import { Stack } from '@mui/material';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import React, { FunctionComponent } from 'react';
import Breadcrumbs from '../../../components/Breadcrumbs';
import SearchInput from '../../../components/SearchInput';
import type { Theme } from '../../../components/Theme';
import ViewSwitchingButtons from '../../../components/ViewSwitchingButtons';
import DataTable from '../../../components/dataGrid/DataTable';
import { useFormatter } from '../../../components/i18n';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import Security from '../../../utils/Security';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import NarrativeCreation from './narratives/NarrativeCreation';
import { narrativeLineFragment } from './narratives/NarrativeLine';
import { narrativesLinesFragment, narrativesLinesQuery } from './narratives/NarrativesLines';
import NarrativesWithSubnarrativesLines from './narratives/NarrativesWithSubnarrativesLines';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from './narratives/__generated__/NarrativesLinesPaginationQuery.graphql';

const LOCAL_STORAGE_KEY = 'narratives';

const Narratives: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Narratives | Techniques'));

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
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
          sx={{ marginBottom: theme.spacing(2) }}
        >
          <SearchInput
            variant="small"
            onSubmit={helpers.handleSearch}
            keyword={searchTerm}
          />

          <Stack direction="row" gap={1}>
            <ViewSwitchingButtons
              handleChangeView={helpers.handleChangeView}
              disableCards={true}
              currentView={view}
              enableSubEntityLines={true}
            />

            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <NarrativeCreation paginationOptions={queryPaginationOptions} />
            </Security>
          </Stack>
        </Stack>

        {queryRef && (
          <React.Suspense
            fallback={(
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <NarrativeWithSubnarrativeLineDummy key={idx} />
                  ))}
              </>
            )}
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
            contextFilters={contextFilters}
            additionalHeaderToggleButtons={[
              (
                <Tooltip key="lines" title={t_i18n('Lines view')}>
                  <ToggleButton
                    value="lines"
                    aria-label="lines"
                  >
                    <FiligranIcon icon={ListViewIcon} size="small" />
                  </ToggleButton>
                </Tooltip>
              ),
              (
                <Tooltip key="subEntityLines" title={t_i18n('Sub entity lines view')}>
                  <ToggleButton
                    value="subEntityLines"
                    aria-label="subEntityLines"
                  >
                    <FiligranIcon icon={SublistViewIcon} size="small" />
                  </ToggleButton>
                </Tooltip>
              )]}
            createButton={(
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
      <div data-testid="narrative-page">
        <Breadcrumbs elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Narratives'), current: true }]} />
        {view === 'lines' ? renderLines() : ''}
        {view === 'subEntityLines' ? renderSubEntityLines() : ''}
      </div>
    </ExportContextProvider>
  );
};
export default Narratives;
