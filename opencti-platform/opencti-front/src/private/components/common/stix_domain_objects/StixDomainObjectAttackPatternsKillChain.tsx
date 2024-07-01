import React, { FunctionComponent, useState } from 'react';
import { graphql, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, FilterAltOutlined, InvertColorsOffOutlined, ViewColumnOutlined, ViewListOutlined } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import Box from '@mui/material/Box';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import StixCoreObjectsExports from '../stix_core_objects/StixCoreObjectsExports';
import SearchInput from '../../../../components/SearchInput';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import StixDomainObjectAttackPatternsKillChainMatrix from './StixDomainObjectAttackPatternsKillChainMatrix';
import StixDomainObjectAttackPatternsKillChainLines from './StixDomainObjectAttackPatternsKillChainLines';
import ExportButtons from '../../../../components/ExportButtons';
import Filters from '../lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import { export_max_size } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  filters: {
    display: 'flex',
    float: 'left',
    alignItems: 'center',
    flexWrap: 'wrap',
    marginRight: 20,
    marginLeft: 20,
    gap: 10,
  },
  buttons: {
    float: 'left',
    display: 'flex',
    margin: '-6px 4px 0 0',
  },
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  parameters: {
    marginBottom: 20,
    padding: 0,
    marginTop: -12,
  },
  export: {
    float: 'right',
    margin: '0 0 0 20px',
  },
}));

export const stixDomainObjectAttackPatternsKillChainQuery = graphql`
    query StixDomainObjectAttackPatternsKillChainQuery(
        $search: String
        $first: Int
        $cursor: ID
        $filters: FilterGroup
    ) {
        ...StixDomainObjectAttackPatternsKillChainContainer_data
        @arguments(
            search: $search
            first: $first
            cursor: $cursor
            filters: $filters
        )
    }
`;

interface StixDomainObjectAttackPatternsKillChainProps {
  data: StixDomainObjectAttackPatternsKillChainContainer_data$data;
  stixDomainObjectId: string;
  handleSearch: (value: string) => void;
  helpers: UseLocalStorageHelpers;
  filters?: FilterGroup;
  handleChangeView: (value: string) => void;
  searchTerm: string;
  currentView?: string;
  paginationOptions: StixDomainObjectAttackPatternsKillChainQuery$variables;
  openExports?: boolean;
  handleToggleExports?: () => void,
  exportContext: { entity_type: string },
  availableFilterKeys: string[];
  defaultStartTime: string;
  defaultStopTime: string;
}

const StixDomainObjectAttackPatternsKillChain: FunctionComponent<StixDomainObjectAttackPatternsKillChainProps> = ({
  data,
  stixDomainObjectId,
  handleSearch,
  helpers,
  filters,
  handleChangeView,
  searchTerm,
  currentView,
  paginationOptions,
  openExports,
  handleToggleExports,
  exportContext,
  availableFilterKeys,
  defaultStartTime,
  defaultStopTime,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [currentModeOnlyActive, setCurrentModeOnlyActive] = useState(false);
  const [currentColorsReversed, setCurrentColorsReversed] = useState(false);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const [queryRef, loadQuery] = useQueryLoader<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
  );
  const refetch = React.useCallback(() => {
    loadQuery(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  const handleToggleModeOnlyActive = () => {
    setCurrentModeOnlyActive(!currentModeOnlyActive);
  };

  const handleToggleColorsReversed = () => {
    setCurrentColorsReversed(!currentColorsReversed);
  };

  const handleAdd = (entity: TargetEntity) => {
    setTargetEntities([entity]);
  };

  let csvData = null;
  if (currentView === 'courses-of-action') {
    csvData = (data.attackPatterns?.edges ?? [])
      .map((n) => n.node.coursesOfAction?.edges ?? [])
      .flat()
      .map((n) => n?.node);
  }
  const exportDisabled = targetEntities.length > export_max_size;

  const exportContextWithEntityType = { ...exportContext, entity_type: 'Attack-Pattern' };
  const paginationOptionsForExport = {
    orderBy: 'name',
    orderMode: 'desc',
    filters: {
      mode: 'and',
      filters: [
        {
          key: 'regardingOf',
          values: [{
            key: 'id',
            values: [stixDomainObjectId],
          }],
        },
      ],
      filterGroups: [],
    },
  };

  return (
    <>
      <div className={classes.parameters} >
        <div style={{ float: 'left', marginRight: 20 }}>
          <SearchInput
            variant="small"
            keyword={searchTerm}
            onSubmit={handleSearch}
          />
        </div>
        <div className={classes.buttons} >
          <Tooltip
            title={
                currentModeOnlyActive
                  ? t_i18n('Display the whole matrix')
                  : t_i18n('Display only used techniques')
              }
          >
            <span>
              <IconButton
                color={currentModeOnlyActive ? 'secondary' : 'primary'}
                onClick={handleToggleModeOnlyActive}
                size="large"
              >
                <FilterAltOutlined fontSize="medium"/>
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip
            title={
                currentColorsReversed
                  ? t_i18n('Disable invert colors')
                  : t_i18n('Enable invert colors')
                }
          >
            <span>
              <IconButton
                color={currentColorsReversed ? 'secondary' : 'primary'}
                onClick={handleToggleColorsReversed}
                size="large"
              >
                <InvertColorsOffOutlined fontSize="medium"/>
              </IconButton>
            </span>
          </Tooltip>
        </div>
        <Box className={classes.filters} >
          <Filters
            availableFilterKeys={availableFilterKeys}
            helpers={helpers}
            searchContext={{ entityTypes: ['Attack-Pattern'] }}
          />
        </Box>
        <div className={classes.buttons} >
          <FilterIconButton
            filters={filters}
            helpers={helpers}
            styleNumber={2}
            redirection
            searchContext={{ entityTypes: ['Attack-Pattern'] }}
          />
        </div>
        <div style={{ float: 'right', margin: 0 }}>
          <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
            <Tooltip title={t_i18n('Matrix view')}>
              <ToggleButton
                onClick={() => handleChangeView('matrix')}
                value={'matrix'}
              >
                <ViewColumnOutlined
                  fontSize="small"
                  color={currentView === 'matrix' ? 'secondary' : 'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Kill chain view')}>
              <ToggleButton
                onClick={() => handleChangeView('list')}
                value={'list'}
              >
                <ViewListOutlined
                  fontSize="small"
                  color={currentView === 'list' ? 'secondary' : 'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Courses of action view')}>
              <ToggleButton
                onClick={() => handleChangeView('courses-of-action')}
                value={'courses-of-action'}
              >
                <ProgressWrench
                  fontSize="small"
                  color={
                      currentView === 'courses-of-action'
                        ? 'secondary'
                        : 'primary'
                    }
                />
              </ToggleButton>
            </Tooltip>
            {typeof handleToggleExports === 'function' && !exportDisabled && (
              <Tooltip title={t_i18n('Open export panel')}>
                <ToggleButton
                  value="export"
                  aria-label="export"
                  onClick={handleToggleExports}
                >
                  <FileDownloadOutlined
                    fontSize="small"
                    color={openExports ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
            )}
            {typeof handleToggleExports === 'function' && exportDisabled && (
              <Tooltip
                title={`${
                  t_i18n(
                    'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                  ) + export_max_size
                })`}
              >
                <span>
                  <ToggleButton
                    size="small"
                    value="export"
                    aria-label="export"
                    disabled={true}
                  >
                    <FileDownloadOutlined fontSize="small"/>
                  </ToggleButton>
                </span>
              </Tooltip>
            )}
          </ToggleButtonGroup>
          <div className={classes.export}>
            <ExportButtons
              domElementId="container"
              name={t_i18n('Attack patterns kill chain')}
              csvData={csvData}
              csvFileName={`${t_i18n('Attack pattern courses of action')}.csv`}
            />
          </div>
        </div>
        <div className="clearfix"/>
      </div>
      <div className={classes.container}>
        {currentView === 'list' && (
          <StixDomainObjectAttackPatternsKillChainLines
            data={data}
            paginationOptions={paginationOptions}
            onDelete={refetch}
            searchTerm={searchTerm}
          />
        )}
        {currentView === 'matrix' && (
          <StixDomainObjectAttackPatternsKillChainMatrix
            data={data}
            searchTerm={searchTerm}
            handleToggleModeOnlyActive={handleToggleModeOnlyActive}
            handleToggleColorsReversed={handleToggleColorsReversed}
            currentColorsReversed={currentColorsReversed}
            currentModeOnlyActive={currentModeOnlyActive}
            handleAdd={handleAdd}
          />
        )}
        {currentView === 'courses-of-action' && (
          <StixDomainObjectAttackPatternsKillChainLines
            data={data}
            paginationOptions={paginationOptions}
            onDelete={refetch}
            searchTerm={searchTerm}
            coursesOfAction={true}
          />
        )}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={false}
            paddingRight={220}
            onCreate={refetch}
            targetStixDomainObjectTypes={['Attack-Pattern']}
            paginationOptions={paginationOptions}
            targetEntities={targetEntities}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
          />
        </Security>
        <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
          <StixCoreObjectsExports
            open={openExports}
            exportType='simple'
            handleToggle={handleToggleExports}
            paginationOptions={paginationOptionsForExport}
            exportContext={exportContextWithEntityType}
          />
        </Security>
      </div>
    </>
  );
};

export default StixDomainObjectAttackPatternsKillChain;
