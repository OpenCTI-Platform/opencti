import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import { HexagonMultipleOutline, ShieldSearch } from 'mdi-material-ui';
import { DescriptionOutlined, DeviceHubOutlined, SettingsOutlined, } from '@mui/icons-material';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { resolveLink } from '../../../../utils/Entity';
import StixCoreObjectReportsHorizontalBars from '../../analyses/reports/StixCoreObjectReportsHorizontalBars';
import StixCoreObjectStixCoreRelationshipsCloud
  from '../stix_core_relationships/StixCoreObjectStixCoreRelationshipsCloud';
import StixDomainObjectGlobalKillChain from './StixDomainObjectGlobalKillChain';
import StixDomainObjectTimeline from './StixDomainObjectTimeline';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { stixDomainObjectThreatKnowledgeStixRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import ExportButtons from '../../../../components/ExportButtons';
import { truncate } from '../../../../utils/String';
import Filters from '../lists/Filters';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import {
  StixDomainObjectThreatKnowledgeReportsNumberQuery$data
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeReportsNumberQuery.graphql';
import {
  StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery.graphql';
import {
  StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$data,
  StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$variables
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    width: 300,
    padding: 20,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemIconSecondary: {
    marginRight: 0,
    color: theme.palette.secondary.main,
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
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 70px 0',
    padding: '15px 15px 15px 15px',
    borderRadius: 6,
  },
  export: {
    float: 'right',
    marginTop: -60,
  },
  filters: {
    float: 'left',
    margin: '10px 0 0 15px',
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    marginRight: 10,
  },
}));

const stixDomainObjectThreatKnowledgeReportsNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeReportsNumberQuery(
    $objectId: String
    $endDate: DateTime
  ) {
    reportsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery(
    $elementId: [String]
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $fromId: [String]
    $fromTypes: [String]
    $toId: [String]
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      elementId: $elementId
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
  displayObservablesStats: boolean;
}

const StixDomainObjectThreatKnowledge: FunctionComponent<StixDomainObjectThreatKnowledgeProps> = ({
   stixDomainObjectId,
   stixDomainObjectType,
   displayObservablesStats,
 }) => {
  const classes = useStyles();
  const { n, t } = useFormatter();
  const LOCAL_STORAGE_KEY = `view-stix-domain-object-${stixDomainObjectId}`;
  const { viewStorage, helpers, paginationOptions: rawPaginationOptions } = usePaginationLocalStorage<StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$variables>(
    LOCAL_STORAGE_KEY,
      {
        filters: {},
        searchTerm: '',
        sortBy: 'created',
        orderAsc: false,
        openExports: false,
        view: 'timeline',
      },
  );
  const {
    filters,
    view,
  } = viewStorage;
  const [timeField, setTimeField] = useState('technical');
  const [nestedRelationships, setNestedRelationships] = useState(false);
  const [openTimeField, setOpenTimeField] = useState(false);
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);

  const handleChangeTimeField = (event: SelectChangeEvent) => {
    setTimeField(event.target.value);
    setNestedRelationships(event.target.value === 'functional'
      ? false
      : nestedRelationships);
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

  const link = `${resolveLink(
    stixDomainObjectType,
  )}/${stixDomainObjectId}/knowledge`;
  const buildPaginationOptions = () => {
    let toTypes: string[] = [];
    if (filters?.entity_type && filters.entity_type.length > 0) {
      if (filters.entity_type.filter((o) => o.id === 'all').length > 0) {
        toTypes = [];
      } else {
        toTypes = filters.entity_type.map((o) => o.id) as string[];
      }
    } else if (view === 'timeline') {
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
    } else {
      toTypes = ['Attack-Pattern', 'Malware', 'Tool', 'Vulnerability'];
    }
    const finalFilters = filters ? R.dissoc('entity_type', filters) : {};
    const finalPaginationOptions = {
      ...rawPaginationOptions,
      elementId: stixDomainObjectId,
      elementWithTargetTypes: toTypes.filter(
          (x) => x.toLowerCase() !== stixDomainObjectType),
      filters: finalFilters,
    };
    if (view === 'timeline') {
      finalPaginationOptions.relationship_type = nestedRelationships
          ? ['stix-relationship']
          : ['stix-core-relationship', 'stix-sighting-relationship'];
      finalPaginationOptions.orderBy = timeField === 'technical' ? 'created_at' : 'start_time';
      finalPaginationOptions.orderMode = 'desc';
    } else {
      finalPaginationOptions.relationship_type = ['uses'];
    }
    return finalPaginationOptions;
  };
  const paginationOptions = buildPaginationOptions();
  return (
    <div>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
          <Card
            variant="outlined"
            classes={{ root: classes.card }}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={stixDomainObjectThreatKnowledgeReportsNumberQuery}
              variables={{
                objectId: stixDomainObjectId,
                endDate: monthsAgo(1),
              }}
              render={({ props }: { props: StixDomainObjectThreatKnowledgeReportsNumberQuery$data }) => {
                if (props && props.reportsNumber) {
                  const { total } = props.reportsNumber;
                  const difference = total - props.reportsNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>
                        {t('Total reports')}
                      </div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t('30 days')}
                      />
                      <div className={classes.icon}>
                        <DescriptionOutlined
                          color="inherit"
                          fontSize="large"
                        />
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
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
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
              render={({ props }: { props: StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>
                        {displayObservablesStats
                          ? t('Total observables')
                          : t('Total indicators')}
                      </div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t('30 days')}
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
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
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
                elementId: stixDomainObjectId,
                endDate: monthsAgo(1),
              }}
              render={({ props }: { props: StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery$data }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <div className={classes.title}>
                        {t('Total relations')}
                      </div>
                      <div className={classes.number}>{n(total)}</div>
                      <ItemNumberDifference
                        difference={difference}
                        description={t('30 days')}
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
      <Grid container={true} spacing={3} style={{ marginTop: -10 }}>
        <Grid item={true} xs={6} style={{ marginBottom: 20 }}>
          <StixCoreObjectReportsHorizontalBars
            stixCoreObjectId={stixDomainObjectId}
            field="created-by.internal_id"
            title={t('Distribution of sources')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginBottom: 20 }}>
          <StixCoreObjectStixCoreRelationshipsCloud
            stixCoreObjectId={stixDomainObjectId}
            stixCoreObjectType="Stix-Core-Object"
            relationshipType="stix-core-relationship"
            title={t('Distribution of relations')}
            field="entity_type"
            noDirection={true}
          />
        </Grid>
      </Grid>
      <Tabs
        value={view}
        indicatorColor="primary"
        textColor="primary"
        onChange={(event, value) => helpers.handleChangeView(value)}
        style={{ margin: '0 0 20px 0' }}
      >
        <Tab label={t('Timeline')} value="timeline" />
        <Tab label={t('Global kill chain')} value="killchain" />
        <div className={classes.filters}>
          <Filters
            availableFilterKeys={[
              'entity_type',
              'markedBy',
              'createdBy',
              'labelledBy',
              'created_start_date',
              'created_end_date',
            ]}
            handleAddFilter={helpers.handleAddFilter}
            allEntityTypes={true}
          />
          <IconButton
            color="primary"
            onClick={handleOpenTimeField}
            style={{ float: 'left', marginTop: -5 }}
            size="large"
          >
            <SettingsOutlined />
          </IconButton>
          <div style={{ float: 'left', margin: '3px 0 0 5px' }}>
            {filters && (R.map((currentFilter) => {
              const label = `${truncate(
                t(`filter_${currentFilter[0]}`),
                20,
              )}`;
              const localFilterMode = currentFilter[0].endsWith('not_eq')
                ? t('AND')
                : t('OR');
              const values = (
                <span>
                  {R.map(
                    (o) => (
                      <span key={o.value as (string | null)}>
                        {o.value && (o.value as string).length > 0
                          ? truncate(o.value, 15)
                          : t('No label')}{' '}
                        {R.last(currentFilter[1])?.value !== o.value && (
                          <code>{localFilterMode}</code>
                        )}{' '}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <span key={label}>
                  <Chip
                    key={currentFilter[0]}
                    classes={{ root: classes.filter }}
                    label={
                      <div>
                        <strong>{label}</strong>: {values}
                      </div>
                    }
                    onDelete={(_) => helpers.handleRemoveFilter(currentFilter[0])}
                  />
                  {R.last(R.toPairs(filters))?.[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, R.toPairs(filters)))}
          </div>
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
              <InputLabel id="timeField">
                {t('Date reference')}
              </InputLabel>
              <Select
                labelId="timeField"
                value={timeField === null ? '' : timeField}
                onChange={handleChangeTimeField}
                fullWidth={true}
              >
                <MenuItem value="technical">{t('Technical date')}</MenuItem>
                <MenuItem value="functional">{t('Functional date')}</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              style={{ marginTop: 20 }}
              control={
                <Switch
                  checked={nestedRelationships}
                  onChange={handleChangeNestedRelationships}
                  name="nested-relationships"
                  color="primary"
                />
              }
              label={t('Display nested relationships')}
            />
          </Popover>
        </div>
      </Tabs>
      <div className={classes.export}>
        <ExportButtons
          domElementId="container"
          name={
            view === 'killchain' ? t('Global kill chain') : t('Timeline')
          }
        />
      </div>
      <QueryRenderer
        query={stixDomainObjectThreatKnowledgeStixRelationshipsQuery}
        variables={{ first: 500, ...paginationOptions }}
        render={({ props }: { props: StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery$data }) => {
          if (props) {
            if (view === 'killchain') {
              return (
                <StixDomainObjectGlobalKillChain
                  data={props}
                  entityLink={link}
                  paginationOptions={paginationOptions}
                  stixDomainObjectId={stixDomainObjectId}
                />
              );
            }
            return (
              <StixDomainObjectTimeline
                data={props}
                entityLink={link}
                paginationOptions={paginationOptions}
                stixDomainObjectId={stixDomainObjectId}
                timeField={timeField}
              />
            );
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </div>
  );
};

export default StixDomainObjectThreatKnowledge;
