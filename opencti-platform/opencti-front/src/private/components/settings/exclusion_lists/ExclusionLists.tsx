import CustomizationMenu from '@components/settings/CustomizationMenu';
import React from 'react';
import ExclusionListCreation from '@components/settings/exclusion_lists/ExclusionListCreation';
import {
  ExclusionListsLinesPaginationQuery,
  ExclusionListsLinesPaginationQuery$variables,
} from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import ExclusionListsLines, { exclusionListsLinesQuery } from '@components/settings/exclusion_lists/ExclusionListsLines';
import { ExclusionListsLineDummy } from '@components/settings/exclusion_lists/ExclusionListsLine';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import Chip from '@mui/material/Chip';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import ItemBoolean from '../../../../components/ItemBoolean';
import ListLines from '../../../../components/list_lines/ListLines';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-exclusion-lists';

const ExclusionLists = () => {
  const { fd, t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ExclusionListsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const { sortBy, orderAsc, searchTerm, filters, numberOfElements } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('ExclusionList', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ExclusionListsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ExclusionListsLinesPaginationQuery>(
    exclusionListsLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: t_i18n('Name'),
        width: '20%',
        isSortable: true,
        render: (node: ExclusionListsLine_node$data) => node.name,
      },
      description: {
        label: t_i18n('Description'),
        width: '30%',
        isSortable: false,
        render: (node: ExclusionListsLine_node$data) => node.description,
      },
      created_at: {
        label: t_i18n('Creation date'),
        width: '10%',
        isSortable: true,
        render: (node: ExclusionListsLine_node$data) => fd(node.created_at),
      },
      enabled: {
        label: t_i18n('Active'),
        width: '10%',
        isSortable: true,
        render: (node: ExclusionListsLine_node$data) => (
          <ItemBoolean
            variant="inList"
            label={node.enabled ? t_i18n('Yes') : t_i18n('No')}
            status={node.enabled}
          />
        ),
      },
      exclusion_list_entity_types: {
        label: t_i18n('Entity type'),
        width: '30%',
        isSortable: false,
        render: (node: ExclusionListsLine_node$data) => (
          <>
            {node.exclusion_list_entity_types.map((type) => (
              <Chip
                key={type}
                variant="outlined"
                label={t_i18n(type)}
                color="primary"
                style={{
                  fontSize: 12,
                  height: 20,
                  marginRight: 7,
                }}
              />
            ))}
          </>
        ),
      },
    };

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}
        numberOfElements={numberOfElements}
        message={t_i18n(
          'TODO : explain this page',
        )}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <ExclusionListsLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <ExclusionListsLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <div style={{ margin: 0, padding: '0 200px 0 0' }}>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Exclusion Lists'), current: true }]} />
      {renderLines()}
      <ExclusionListCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

export default ExclusionLists;
