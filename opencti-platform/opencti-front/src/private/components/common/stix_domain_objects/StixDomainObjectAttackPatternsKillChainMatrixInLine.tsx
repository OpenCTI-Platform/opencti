import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import {
  stixDomainObjectAttackPatternsKillChainContainerFragment,
  stixDomainObjectAttackPatternsKillChainContainerLineFragment,
} from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChainContainer';
import { stixDomainObjectAttackPatternsKillChainQuery } from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChain';
import ToggleButton from '@mui/material/ToggleButton';
import { ViewColumnOutlined } from '@mui/icons-material';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import FiligranIcon from '@components/common/FiligranIcon';
import { ProgressWrench } from 'mdi-material-ui';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { truncate } from '../../../../utils/String';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  paginationOptions: StixDomainObjectAttackPatternsKillChainQuery$variables;
}

const StixDomainObjectAttackPatternsKillChainMatrixInline: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    storageKey,
    entityId,
    currentView,
    paginationOptions,
  },
) => {
  const { t_i18n } = useFormatter();
  const dataColumns = {
    entity_type: { percentWidth: 11 },
    killChainPhase: { percentWidth: 22 },
    x_mitre_id: { percentWidth: 10 },
    name: {
      percentWidth: 20,
      render: ({ name }: { name: string }, { column: { size } }: { column: { size: number } }) => (<Tooltip title={name}>{truncate(name, size * 0.113)}</Tooltip>),
    },
    objectLabel: { percentWidth: 15 },
    created: { percentWidth: 12 },
    objectMarking: { percentWidth: 10 },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: 'matrix-in-line',
  };

  const { viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixDomainObjectAttackPatternsKillChainQuery$variables>(
    storageKey,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Attack-Pattern']);
  const contextFilters = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Attack-Pattern'], mode: 'or', operator: 'eq' },
      {
        key: 'regardingOf',
        values: [
          { key: 'id', values: [entityId] },
        ],
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StixDomainObjectAttackPatternsKillChainQuery$variables;

  const queryRef = useQueryLoading<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: stixDomainObjectAttackPatternsKillChainQuery,
    linesFragment: stixDomainObjectAttackPatternsKillChainContainerFragment,
    queryRef,
    nodePath: ['attackPatterns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixDomainObjectAttackPatternsKillChainQuery>;

  return (
    <div
      style={{
        transform: 'translateY(-12px)',
      }}
    >
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixDomainObjectAttackPatternsKillChainContainer_data$data) => (data.attackPatterns?.edges ?? []).map((n) => n.node)}
          storageKey={storageKey}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={stixDomainObjectAttackPatternsKillChainContainerLineFragment}
          exportContext={{ entity_type: 'Attack-Pattern' }}
          additionalHeaderButtons={[
            (<ToggleButton key="matrix" value="matrix" aria-label="matrix">
              <Tooltip title={t_i18n('Matrix view')}>
                <ViewColumnOutlined fontSize="small" color="primary" />
              </Tooltip>
            </ToggleButton>),
            (<Tooltip key="matrix-in-line" title={t_i18n('Matrix in line view')}>
              <ToggleButton key="matrix-in-line" value="matrix-in-line" aria-label="matrix-in-line">
                <FiligranIcon icon={ListViewIcon} size="small" color={currentView === 'matrix-in-line' ? 'secondary' : 'primary'} />
              </ToggleButton>
            </Tooltip>
            ),
            (<Tooltip key="list" title={t_i18n('Kill chain view')}>
              <ToggleButton key="list" value="list" aria-label="list">
                <FiligranIcon icon={SublistViewIcon} size="small" color={currentView === 'list' ? 'secondary' : 'primary'} />
              </ToggleButton>
            </Tooltip>
            ),
            (<ToggleButton key="courses-of-action" value="courses-of-action" aria-label="courses-of-action">
              <Tooltip title={t_i18n('Courses of action view')}>
                <ProgressWrench color="primary" fontSize="small" />
              </Tooltip>
            </ToggleButton>),
          ]}
        />
      )}
    </div>
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrixInline;
