import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, InvertColorsOffOutlined, ViewColumnOutlined } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import IconButton from '@mui/material/IconButton';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import Box from '@mui/material/Box';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import StixDomainObjectAttackPatternsKillChainMatrixInline from '@components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChainMatrixInLine';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import FiligranIcon from '@components/common/FiligranIcon';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { AttackPatternsMatrixColumnsQuery } from '@components/techniques/attack_patterns/__generated__/AttackPatternsMatrixColumnsQuery.graphql';
import { attackPatternsMatrixColumnsFragment, attackPatternsMatrixColumnsQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrixColumns';
import * as R from 'ramda';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/__generated__/AttackPatternsMatrixColumns_data.graphql';
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
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import useHelper from '../../../../utils/hooks/useHelper';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';

export const stixDomainObjectAttackPatternsKillChainQuery = graphql`
  query StixDomainObjectAttackPatternsKillChainQuery(
    $search: String
    $first: Int
    $cursor: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixDomainObjectAttackPatternsKillChainContainer_data
    @arguments(
      search: $search
      first: $first
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
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
  storageKey: string;
  killChainDataQueryRef: PreloadedQuery<AttackPatternsMatrixColumnsQuery>;
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
  storageKey,
  killChainDataQueryRef,
}) => {
  const { t_i18n } = useFormatter();
  const { setState: setCreateRelationshipContext } = useContext(CreateRelationshipContext);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [currentColorsReversed, setCurrentColorsReversed] = useState(false);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const [selectedKillChain, setSelectedKillChain] = useState('mitre-attack');
  const [queryRef, loadQuery] = useQueryLoader<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
  );

  const refetch = React.useCallback(() => {
    loadQuery(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);
  useEffect(() => {
    setCreateRelationshipContext({
      onCreate: refetch,
    });
  }, []);

  const handleToggleColorsReversed = () => {
    setCurrentColorsReversed(!currentColorsReversed);
  };

  const handleAdd = (entity: TargetEntity) => {
    setTargetEntities([entity]);
  };

  const handleKillChainChange = (event: SelectChangeEvent<unknown>) => {
    setSelectedKillChain(event.target.value as string);
  };

  let csvData = null;
  if (currentView === 'courses-of-action') {
    csvData = (data.attackPatterns?.edges ?? [])
      .map((n) => n.node.coursesOfAction?.edges ?? [])
      .flat()
      .map((n) => n?.node);
  }

  const killChainsData = usePreloadedFragment<AttackPatternsMatrixColumnsQuery, AttackPatternsMatrixColumns_data$key>({
    queryDef: attackPatternsMatrixColumnsQuery,
    fragmentDef: attackPatternsMatrixColumnsFragment,
    queryRef: killChainDataQueryRef,
  });
  const killChainsPhaseData = killChainsData.attackPatternsMatrix?.attackPatternsOfPhases ?? [];
  const killChains = R.uniq(killChainsPhaseData.map((a) => a.kill_chain_name))
    .sort((a, b) => a.localeCompare(b));

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
  let activKillChainValue;
  if (killChains.includes(selectedKillChain)) {
    activKillChainValue = selectedKillChain;
  } else {
    activKillChainValue = killChains.length > 0 ? killChains[0] : undefined;
  }

  return (
    <>
      {currentView !== 'matrix-in-line' && <div
        style={{
          marginBottom: 20,
          padding: 0,
          marginTop: -12,
        }}
                                           >
        <div
          style={{
            float: 'left',
          }}
        >
          <SearchInput
            variant="small"
            keyword={searchTerm}
            onSubmit={handleSearch}
          />
        </div>
        <Box
          style={{
            display: 'flex',
            float: 'left',
            alignItems: 'center',
            flexWrap: 'wrap',
            marginRight: 20,
            marginLeft: 8,
            gap: 10,
          }}
        >
          <Filters
            availableFilterKeys={availableFilterKeys}
            helpers={helpers}
            searchContext={{ entityTypes: ['Attack-Pattern'] }}
          />
        </Box>
        <div
          style={{
            float: 'left',
            display: 'flex',
            margin: '-6px 4px 0 0',
          }}
        >
          <FilterIconButton
            filters={filters}
            helpers={helpers}
            styleNumber={2}
            redirection
            searchContext={{ entityTypes: ['Attack-Pattern'] }}
          />
        </div>
        {currentView === 'matrix' && (
        <div
          style={{
            float: 'left',
            display: 'flex',
            padding: '0 10px 2px 10px',
          }}
        >
          <InputLabel
            style={{
              padding: '10px 10px 0 0',
            }}
          >
            {t_i18n('Kill chain :')}
          </InputLabel>
          <FormControl
            style={{
              paddingTop: 10,
            }}
          >
            <Select
              size="small"
              value={activKillChainValue}
              onChange={handleKillChainChange}
            >
              {killChains.map((killChainName) => (
                <MenuItem key={killChainName} value={killChainName}>
                  {killChainName}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </div>
        )}
        <div style={{ float: 'right', margin: 0 }}>
          {currentView !== 'list' && currentView !== 'courses-of-action' && currentView !== 'matrix-in-line' && (
          <Tooltip
            title={
                    currentColorsReversed
                      ? t_i18n('Disable invert colors')
                      : t_i18n('Enable invert colors')
                  }
          >
            <span
              style={{
                marginRight: 10,
              }}
            >
              <IconButton
                style={{
                  transform: 'translateY(-5px)',
                }}
                color={currentColorsReversed ? 'secondary' : 'primary'}
                onClick={handleToggleColorsReversed}
                size="large"
              >
                <InvertColorsOffOutlined fontSize="medium"/>
              </IconButton>
            </span>
          </Tooltip>
          )}
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
            <Tooltip title={t_i18n('Matrix in line view')}>
              <ToggleButton
                onClick={() => handleChangeView('matrix-in-line')}
                value={'matrix-in-line'}
              >
                <FiligranIcon icon={ListViewIcon}
                  size="small"
                  color={currentView === 'matrix-in-line' ? 'secondary' : 'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Kill chain view')}>
              <ToggleButton
                onClick={() => handleChangeView('list')}
                value={'list'}
              >
                <FiligranIcon icon={SublistViewIcon}
                  size="small"
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

          <div
            style={{
              float: 'right',
              margin: '0 0 0 20px',
            }}
          >
            <ExportButtons
              domElementId="container"
              name={t_i18n('Attack patterns kill chain')}
              csvData={csvData}
              csvFileName={`${t_i18n('Attack pattern courses of action')}.csv`}
            />
          </div>
        </div>
        <div className="clearfix"/>
      </div>}
      <div
        style={{
          width: '100%',
          height: '100%',
          margin: 0,
          padding: 0,
        }}
      >
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
            handleToggleColorsReversed={handleToggleColorsReversed}
            currentColorsReversed={currentColorsReversed}
            handleAdd={handleAdd}
            selectedKillChain={selectedKillChain}
          />
        )}
        {currentView === 'matrix-in-line' && (
          <StixDomainObjectAttackPatternsKillChainMatrixInline
            storageKey={storageKey}
            entityId={stixDomainObjectId}
            currentView={currentView}
            paginationOptions={paginationOptions}
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
        {!isFABReplaced && (
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
        )}
        {currentView !== 'matrix-in-line' && <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
          <StixCoreObjectsExports
            open={openExports}
            exportType='simple'
            handleToggle={handleToggleExports}
            paginationOptions={paginationOptionsForExport}
            exportContext={exportContextWithEntityType}
          />
        </Security>}
      </div>
    </>
  );
};

export default StixDomainObjectAttackPatternsKillChain;
