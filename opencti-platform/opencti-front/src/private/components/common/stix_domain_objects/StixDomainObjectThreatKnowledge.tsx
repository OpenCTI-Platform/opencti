import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import { HexagonMultipleOutline, ShieldSearch } from 'mdi-material-ui';
import { DescriptionOutlined, DeviceHubOutlined, SettingsOutlined } from '@mui/icons-material';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import IconButton from '@common/button/IconButton';
import Popover from '@mui/material/Popover';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import makeStyles from '@mui/styles/makeStyles';
import {
  StixDomainObjectThreatKnowledgeContainersNumberQuery$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeContainersNumberQuery.graphql';
import {
  StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery.graphql';
import {
  StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$data,
  StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery.graphql';
import StixDomainObjectDiamond from '@components/common/stix_domain_objects/StixDomainObjectDiamond';
import { stixDomainObjectThreatDiamondQuery } from '@components/common/stix_domain_objects/StixDomainObjectThreatDiamondQuery';
import { StixDomainObjectThreatDiamondQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatDiamondQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { resolveLink } from '../../../../utils/Entity';
import StixDomainObjectGlobalKillChain from './StixDomainObjectGlobalKillChain';
import StixDomainObjectTimeline from './StixDomainObjectTimeline';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { stixDomainObjectThreatKnowledgeStixRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import ExportButtons from '../../../../components/ExportButtons';
import Filters from '../lists/Filters';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import type { Theme } from '../../../../components/Theme';
import {
  emptyFilterGroup,
  getDefaultFilterObject,
  isFilterGroupNotEmpty,
  useFilterDefinition,
  useRemoveIdAndIncorrectKeysFromFilterGroupObject,
} from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import StixCoreObjectReportsHorizontalBar from '../../analyses/reports/StixCoreObjectReportsHorizontalBar';
import { useInitCreateRelationshipContext } from '../stix_core_relationships/CreateRelationshipContextProvider';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    width: 300,
    padding: 20,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 4,
    position: 'relative',
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: '#a8a8a8',
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
  export: {
    float: 'right',
  },
  filters: {
    float: 'left',
    display: 'flex',
    alignItems: 'center',
    gap: 5,
    flexWrap: 'wrap',
    margin: '5px 0 0 5px',
  },
}));

const stixDomainObjectThreatKnowledgeContainersNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeContainersNumberQuery(
    $objectId: String
    $endDate: DateTime
  ) {
    containersNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery(
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $fromId: [String]
    $fromTypes: [String]
    $toId: [String]
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      relationship_type: $relationship_type
      fromId: $fromId
      fromTypes: $fromTypes
      toId: $toId
      toTypes: $toTypes
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

interface StixDomainObjectThreatKnowledgeProps {
  stixDomainObjectId: string;
  stixDomainObjectType: string;
  displayObservablesStats?: boolean;
  stixDomainObjectName?: string;
}

const StixDomainObjectThreatKnowledge: FunctionComponent<
  StixDomainObjectThreatKnowledgeProps
/*
  TODO
  we should reword the component to be able to manipulate data easier
  in fact, page update is complicated, if not impossible
  it could be interesting to use the relay provider and rework the uses of graphql queries
*/
> = ({ stixDomainObjectId, stixDomainObjectName, stixDomainObjectType, displayObservablesStats }) => {
  const classes = useStyles();
  const { n, t_i18n } = useFormatter();
  const [viewType, setViewType] = useState('diamond');
  const [timeField, setTimeField] = useState('technical');
  const [nestedRelationships, setNestedRelationships] = useState(false);
  const [openTimeField, setOpenTimeField] = useState(false);
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);

  // Reset 'Create Relationship' target types
  useInitCreateRelationshipContext();

  const LOCAL_STORAGE_KEY = `stix-domain-object-${stixDomainObjectId}`;
  const link = `${resolveLink(stixDomainObjectType)}/${stixDomainObjectId}/knowledge`;

  let toTypes = ['Attack-Pattern', 'Malware', 'Tool', 'Vulnerability'];
  if (viewType === 'timeline') {
    toTypes = [
      'Attack-Pattern',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
      'Vulnerability',
      'Narrative',
      'Channel',
      'Sector',
      'Organization',
      'Individual',
      'Region',
      'Country',
      'City',
      'Note',
      'Event',
    ];
  }
  const {
    viewStorage,
    helpers,
    paginationOptions: rawPaginationOptions,
  } = usePaginationLocalStorage<StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {
        ...emptyFilterGroup,
        filters: [
          {
            ...getDefaultFilterObject('elementWithTargetTypes', useFilterDefinition('elementWithTargetTypes', ['Stix-Core-Object'])),
            // For now its impossible to use the current element type for filtering
            // The filter will be always true as the element is always part of the relations
            // TODO Implement a new composite filter for relationships
            values: toTypes.filter((type) => type !== stixDomainObjectType),
          },
        ],
      },
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
    },
  );
  const { filters } = viewStorage;

  const handleChangeViewType = (type: string) => {
    if (type) {
      setViewType(type);
    }
  };

  const handleChangeTimeField = (event: SelectChangeEvent) => {
    setTimeField(event.target.value);
    setNestedRelationships(
      event.target.value === 'functional' ? false : nestedRelationships,
    );
  };

  const handleChangeNestedRelationships = (event: React.ChangeEvent<HTMLInputElement>) => {
    setNestedRelationships(event.target.checked);
    setTimeField(event.target.checked ? 'technical' : timeField);
  };

  const handleOpenTimeField = (event: React.MouseEvent) => {
    setOpenTimeField(true);
    setAnchorEl(event.currentTarget);
  };

  const handleCloseTimeField = () => {
    setOpenTimeField(false);
  };

  let relationshipTypes = ['uses'];
  let paginationOrderBy = rawPaginationOptions.orderBy;
  let paginationOrderMode = rawPaginationOptions.orderMode;
  if (viewType === 'timeline') {
    paginationOrderBy = timeField === 'technical' ? 'created_at' : 'start_time';
    paginationOrderMode = 'desc';
    relationshipTypes = nestedRelationships
      ? ['stix-relationship']
      : ['stix-core-relationship', 'stix-sighting-relationship'];
  }
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'relationship_type', operator: 'eq', mode: 'or', values: relationshipTypes },
      { key: 'fromOrToId', operator: 'eq', mode: 'or', values: [stixDomainObjectId] },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...rawPaginationOptions,
    orderMode: paginationOrderMode,
    orderBy: paginationOrderBy,
    filters: contextFilters,
  };

  let exportName = `${stixDomainObjectName ? `${stixDomainObjectName} - ${t_i18n('Diamond')}` : t_i18n('Diamond')}`;
  if (viewType === 'timeline') {
    exportName = `${stixDomainObjectName ? `${stixDomainObjectName} - ${t_i18n('Timeline')}` : t_i18n('Timeline')}`;
  }
  if (viewType === 'killchain') {
    exportName = `${stixDomainObjectName ? `${stixDomainObjectName} - ${t_i18n('Global kill chain')}` : t_i18n('Global kill chain')}`;
  }
  return (
    <>
      <Grid container={true} spacing={3}>
        <Grid item xs={4}>
          <Card
            variant="outlined"
            classes={{ root: classes.card }}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={stixDomainObjectThreatKnowledgeContainersNumberQuery}
              variables={{
                objectId: stixDomainObjectId,
                endDate: monthsAgo(1),
              }}
              render={({
                props,
              }: {
                props: StixDomainObjectThreatKnowledgeContainersNumberQuery$data;
              }) => {
                if (props && props.containersNumber) {
                  const { total } = props.containersNumber;
                  const difference = total - props.containersNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>{t_i18n('Total analyses')}</div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t_i18n('30 days')}
                      />
                      <div className={classes.icon}>
                        <DescriptionOutlined color="inherit" fontSize="large" />
                      </div>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
        <Grid item xs={4}>
          <Card
            variant="outlined"
            classes={{ root: classes.card }}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={
                stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
              }
              variables={{
                toId: stixDomainObjectId,
                fromTypes: displayObservablesStats
                  ? ['Stix-Cyber-Observable']
                  : 'Indicator',
                endDate: monthsAgo(1),
              }}
              render={({
                props,
              }: {
                props: StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data;
              }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>
                        {displayObservablesStats
                          ? t_i18n('Total observables')
                          : t_i18n('Total indicators')}
                      </div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t_i18n('30 days')}
                      />
                      <div className={classes.icon}>
                        {displayObservablesStats ? (
                          <HexagonMultipleOutline
                            color="inherit"
                            fontSize="large"
                          />
                        ) : (
                          <ShieldSearch color="inherit" fontSize="large" />
                        )}
                      </div>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
        <Grid item xs={4}>
          <Card
            variant="outlined"
            classes={{ root: classes.card }}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={
                stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
              }
              variables={{
                fromOrToId: stixDomainObjectId,
                endDate: monthsAgo(1),
              }}
              render={({
                props,
              }: {
                props: StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data;
              }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>
                        {t_i18n('Total relations')}
                      </div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t_i18n('30 days')}
                      />
                      <div className={classes.icon}>
                        <DeviceHubOutlined color="inherit" fontSize="large" />
                      </div>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
      </Grid>
      <StixCoreObjectReportsHorizontalBar
        stixCoreObjectId={stixDomainObjectId}
        field="created-by.internal_id"
        title={t_i18n('Distribution of reports')}
      />
      <Tabs
        value={viewType}
        indicatorColor="primary"
        textColor="primary"
        onChange={(_, value) => handleChangeViewType(value)}
        style={{ float: 'left' }}
      >
        <Tab label={t_i18n('Diamond')} value="diamond" />
        <Tab label={t_i18n('Timeline')} value="timeline" />
        <Tab label={t_i18n('Global kill chain')} value="killchain" />
      </Tabs>
      {viewType !== 'diamond' && (
        <div className={classes.filters}>
          <Filters
            helpers={helpers}
            availableFilterKeys={[
              'elementWithTargetTypes',
              'objectMarking',
              'createdBy',
              'objectLabel',
              'created',
              'toId',
            ]}
            handleAddFilter={helpers.handleAddFilter}
            searchContext={{ entityTypes: ['stix-core-relationship'] }}
          />
          <IconButton color="primary" onClick={handleOpenTimeField} size="small">
            <SettingsOutlined fontSize="small" />
          </IconButton>
          <Popover
            classes={{ paper: classes.container }}
            open={openTimeField}
            anchorEl={anchorEl}
            onClose={handleCloseTimeField}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'center',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'center',
            }}
            elevation={1}
          >
            <FormControl style={{ width: '100%' }}>
              <InputLabel id="timeField">{t_i18n('Date reference')}</InputLabel>
              <Select
                labelId="timeField"
                value={timeField === null ? '' : timeField}
                onChange={handleChangeTimeField}
                fullWidth={true}
              >
                <MenuItem value="technical">{t_i18n('Technical date')}</MenuItem>
                <MenuItem value="functional">{t_i18n('Functional date')}</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              style={{ marginTop: 20 }}
              control={(
                <Switch
                  checked={nestedRelationships}
                  onChange={handleChangeNestedRelationships}
                  name="nested-relationships"
                  color="primary"
                />
              )}
              label={t_i18n('Display nested relationships')}
            />
          </Popover>
        </div>
      )}
      <div className={classes.export}>
        <ExportButtons domElementId="container" name={exportName} />
      </div>
      <div className="clearfix" />
      {viewType !== 'diamond' && (
        <FilterIconButton
          styleNumber={2}
          helpers={helpers}
          filters={filters}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          entityTypes={['stix-core-relationship']}
        />
      )}
      {viewType === 'diamond' ? (
        <QueryRenderer
          query={stixDomainObjectThreatDiamondQuery}
          variables={{ id: stixDomainObjectId }}
          render={({
            props,
          }: {
            props: StixDomainObjectThreatDiamondQuery$data;
          }) => {
            if (props) {
              return (
                <StixDomainObjectDiamond data={props} entityLink={link} />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      ) : (
        <QueryRenderer
          query={stixDomainObjectThreatKnowledgeStixRelationshipsQuery}
          variables={{ first: 500, ...queryPaginationOptions }}
          render={({
            props,
          }: {
            props: StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$data;
          }) => {
            if (props) {
              if (viewType === 'killchain') {
                return (
                  <StixDomainObjectGlobalKillChain
                    data={props}
                    entityLink={link}
                    paginationOptions={queryPaginationOptions}
                    stixDomainObjectId={stixDomainObjectId}
                  />
                );
              }
              return (
                <StixDomainObjectTimeline
                  data={props}
                  entityLink={link}
                  paginationOptions={queryPaginationOptions}
                  stixDomainObjectId={stixDomainObjectId}
                  timeField={timeField}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      )}
    </>
  );
};

export default StixDomainObjectThreatKnowledge;
