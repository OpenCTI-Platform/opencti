import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, ViewColumnOutlined, VisibilityOutlined } from '@mui/icons-material';
import { ProgressWrench, RelationManyToMany } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
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
import { attackPatternsMatrixColumnsFragment } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import * as R from 'ramda';
import { AttackPatternsMatrixColumns_data$key } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import StixCoreRelationships from '@components/common/stix_core_relationships/StixCoreRelationships';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import { attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import EntitySelect, { EntityOption } from '@components/common/form/EntitySelect';
import { IconButton } from '@mui/material';
import {
  StixDomainObjectAttackPatternsKillChainOverlapQuery$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainOverlapQuery.graphql';
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
import { fetchQuery } from '../../../../relay/environment';
import { containerTypes } from '../../../../utils/hooks/useAttributes';
import { useInitCreateRelationshipContext } from '../stix_core_relationships/CreateRelationshipContextProvider';

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

const stixDomainObjectAttackPatternsKillChainOverlapQuery = graphql`
  query StixDomainObjectAttackPatternsKillChainOverlapQuery($types: [String], $count: Int!, $filters: FilterGroup) {
    stixCoreObjects(types: $types, first: $count, filters: $filters) {
      edges {
        node {
          id
          entity_type
        }
      }
    }
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
  handleToggleExports?: () => void;
  exportContext: { entity_type: string };
  availableFilterKeys: string[];
  defaultStartTime?: string;
  defaultStopTime?: string;
  storageKey: string;
  killChainDataQueryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
  entityType: string;
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
  entityType,
}) => {
  const { t_i18n } = useFormatter();
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const [selectedKillChain, setSelectedKillChain] = useState('mitre-attack');
  const [selectedSecurityPlatforms, setSelectedSecurityPlatforms] = useState<EntityOption[]>([]);
  const [attackPatternIdsToOverlap, setAttackPatternIdsToOverlap] = useState<string[] | undefined>();
  const [isModeOnlyActive, setIsModeOnlyActive] = useState<boolean>(false);
  const [queryRef, loadQuery] = useQueryLoader<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
  );

  const isSecurityPlatform = entityType === 'SecurityPlatform';
  const displayButtons = !containerTypes.includes(entityType);

  const refetch = React.useCallback(() => {
    loadQuery(paginationOptions, { fetchPolicy: 'store-and-network' });
  }, [queryRef, currentView]);

  useInitCreateRelationshipContext({
    onCreate: refetch,
    relationshipTypes: ['uses', 'related-to', 'should-cover'],
    reversed: false,
  });

  const handleAdd = (entity: TargetEntity) => {
    setTargetEntities([entity]);
  };

  const handleKillChainChange = (event: SelectChangeEvent<unknown>) => {
    setSelectedKillChain(event.target.value as string);
  };

  const getAttackPatternIdsToOverlap = async (entityIdsToOverlap: string[]) => {
    if (entityIdsToOverlap.length === 0) return undefined;

    const { stixCoreObjects } = await fetchQuery(
      stixDomainObjectAttackPatternsKillChainOverlapQuery,
      {
        count: 1000,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              mode: 'or',
              values: ['Attack-Pattern'],
            },
            {
              key: 'regardingOf',
              operator: 'eq',
              mode: 'and',
              values: [
                {
                  key: 'id',
                  values: entityIdsToOverlap,
                  operator: 'eq',
                  mode: 'or',
                },
                {
                  key: 'relationship_type',
                  values: ['should-cover'],
                  operator: 'eq',
                  mode: 'or',
                },
              ],
            },
          ],
          filterGroups: [],
        },
      },
    ).toPromise() as StixDomainObjectAttackPatternsKillChainOverlapQuery$data;

    return stixCoreObjects?.edges?.map(({ node }) => node.id);
  };

  const handleSecurityPlatformsChange = async (newSelectedSecurityPlatforms: EntityOption[]) => {
    setSelectedSecurityPlatforms(newSelectedSecurityPlatforms);

    const entityIds = newSelectedSecurityPlatforms.map(({ value }) => value);
    const attackPatternIds = await getAttackPatternIdsToOverlap(entityIds);
    setAttackPatternIdsToOverlap(attackPatternIds);
  };

  let csvData = null;
  if (currentView === 'courses-of-action') {
    csvData = (data.attackPatterns?.edges ?? [])
      .map((n) => n.node.coursesOfAction?.edges ?? [])
      .flat()
      .map((n) => n?.node);
  }

  const killChainsData = usePreloadedFragment<AttackPatternsMatrixQuery, AttackPatternsMatrixColumns_data$key>({
    queryDef: attackPatternsMatrixQuery,
    fragmentDef: attackPatternsMatrixColumnsFragment,
    queryRef: killChainDataQueryRef,
  });

  const killChainsPhaseData = killChainsData.attackPatternsMatrix?.attackPatternsOfPhases ?? [];
  const killChains = R.uniq(killChainsPhaseData.map((a) => a.kill_chain_name))
    .sort((a, b) => a.localeCompare(b));

  if (killChains.length > 0 && !killChains.includes(selectedKillChain)) {
    setSelectedKillChain(killChains[0]);
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

  const matrixViewButton = (
    <Tooltip title={t_i18n('Matrix view')} key="matrix">
      <ToggleButton
        aria-label="matrix"
        onClick={() => handleChangeView('matrix')}
        value="matrix"
      >
        <ViewColumnOutlined
          fontSize="small"
          color={currentView === 'matrix' ? 'secondary' : 'primary'}
        />
      </ToggleButton>
    </Tooltip>
  );
  const matrixInLineViewButton = (
    <Tooltip title={t_i18n('Matrix in line view')} key="matrix-in-line">
      <ToggleButton value="matrix-in-line" aria-label="matrix-in-line" onClick={() => handleChangeView('matrix-in-line')}>
        <FiligranIcon icon={ListViewIcon} size="small" color={currentView === 'matrix-in-line' ? 'secondary' : 'primary'} />
      </ToggleButton>
    </Tooltip>
  );
  const killChainViewButton = (
    <Tooltip title={t_i18n('Kill chain view')} key="list">
      <ToggleButton value="list" aria-label="list" onClick={() => handleChangeView('list')}>
        <FiligranIcon icon={SublistViewIcon} size="small" color={currentView === 'list' ? 'secondary' : 'primary'} />
      </ToggleButton>
    </Tooltip>
  );
  const courseOfActionView = (
    <Tooltip title={t_i18n('Courses of action view')} key="courses-of-action">
      <ToggleButton value="courses-of-action" aria-label="courses-of-action" onClick={() => handleChangeView('courses-of-action')}>
        <ProgressWrench fontSize="small" color={currentView === 'courses-of-action' ? 'secondary' : 'primary'} />
      </ToggleButton>
    </Tooltip>
  );
  const relationshipsView = (
    <Tooltip title={t_i18n('Relationships view')} key="relationships">
      <ToggleButton value="relationships" aria-label="relationships" onClick={() => handleChangeView('relationships')}>
        <RelationManyToMany fontSize="small" color={currentView === 'relationships' ? 'secondary' : 'primary'} />
      </ToggleButton>
    </Tooltip>
  );
  const viewButtons = [matrixViewButton, matrixInLineViewButton, killChainViewButton, courseOfActionView, relationshipsView];

  return (
    <>
      {currentView !== 'matrix-in-line' && currentView !== 'relationships' && (
        <div
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
          <Box
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
          </Box>
          {currentView === 'matrix' && (
            <>
              <Box
                style={{
                  float: 'left',
                  display: 'flex',
                  paddingInline: 10,
                  paddingBlock: 10,
                  gap: 1,
                }}
              >
                <InputLabel style={{ paddingInlineEnd: 10 }}>
                  {t_i18n('Kill chain :')}
                </InputLabel>
                <FormControl>
                  <Select
                    size="small"
                    value={selectedKillChain}
                    onChange={handleKillChainChange}
                  >
                    {killChains.map((killChainName) => (
                      <MenuItem key={killChainName} value={killChainName}>
                        {killChainName}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
              <Box
                style={{
                  float: 'left',
                  display: 'flex',
                  marginBlockStart: -4,
                  paddingInline: 10,
                }}
              >
                <Tooltip
                  title={
                    isModeOnlyActive
                      ? t_i18n('Display the whole matrix')
                      : t_i18n('Display only used techniques')
                  }
                >
                  <span>
                    <IconButton
                      color={isModeOnlyActive ? 'secondary' : 'primary'}
                      onClick={() => setIsModeOnlyActive((value) => !value)}
                    >
                      <VisibilityOutlined />
                    </IconButton>
                  </span>
                </Tooltip>
              </Box>

              {!isSecurityPlatform && (
                <Box
                  style={{
                    float: 'left',
                    display: 'flex',
                    paddingInline: 10,
                  }}
                >
                  <FormControl style={{ display: 'flex', paddingInlineEnd: 10, minWidth: 300, maxWidth: 500 }}>
                    <EntitySelect
                      multiple
                      variant="outlined"
                      size="small"
                      value={selectedSecurityPlatforms}
                      label={t_i18n('Compare with my security posture')}
                      types={['SecurityPlatform']}
                      onChange={(newSelectedSecurityPlatforms) => {
                        handleSecurityPlatformsChange(newSelectedSecurityPlatforms as EntityOption[]);
                      }}
                    />
                  </FormControl>
                </Box>
              )}
            </>
          )}
          {displayButtons
            && (
              <div style={{ float: 'right', margin: 0 }} id="container-view-buttons">
                <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
                  {[...viewButtons]}
                  {typeof handleToggleExports === 'function' && (
                    <Tooltip
                      key="export"
                      title={
                        exportDisabled
                          ? `${t_i18n('Export is disabled because too many entities are targeted (maximum number of entities is: ') + export_max_size})`
                          : t_i18n('Open export panel')
                      }
                    >
                      <ToggleButton
                        size="small"
                        value="export"
                        aria-label="export"
                        onClick={exportDisabled ? undefined : handleToggleExports}
                        disabled={exportDisabled}
                      >
                        <FileDownloadOutlined
                          fontSize="small"
                          color={!exportDisabled && openExports ? 'secondary' : 'primary'}
                        />
                      </ToggleButton>
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
            )}
          <div className="clearfix" />
        </div>
      )}
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
            handleAdd={handleAdd}
            selectedKillChain={selectedKillChain}
            attackPatternIdsToOverlap={attackPatternIdsToOverlap}
            entityType={entityType}
            isModeOnlyActive={isModeOnlyActive}
          />
        )}
        {currentView === 'matrix-in-line' && (
          <StixDomainObjectAttackPatternsKillChainMatrixInline
            storageKey={storageKey}
            entityId={stixDomainObjectId}
            currentView={currentView}
            viewButtons={viewButtons}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
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
        {currentView === 'relationships' && (
          <StixCoreRelationships
            entityId={stixDomainObjectId}
            currentView={currentView}
            viewButtons={viewButtons}
            targetTypes={['Attack-Pattern']}
            direction="fromEntity"
            relationshipTypes={['uses', 'should-cover']}
            storageKey={storageKey}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
          />
        )}
        {currentView !== 'relationships' && currentView !== 'matrix-in-line' && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipCreationFromEntity
              entityId={stixDomainObjectId}
              isRelationReversed={false}
              paddingRight={displayButtons ? 220 : 0}
              onCreate={refetch}
              targetStixDomainObjectTypes={['Attack-Pattern']}
              paginationOptions={paginationOptions}
              targetEntities={targetEntities}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
            />
          </Security>
        )}
        {currentView !== 'matrix-in-line' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCoreObjectsExports
              open={openExports}
              exportType="simple"
              handleToggle={handleToggleExports}
              paginationOptions={paginationOptionsForExport}
              exportContext={exportContextWithEntityType}
            />
          </Security>
        )}
      </div>
    </>
  );
};

export default StixDomainObjectAttackPatternsKillChain;
