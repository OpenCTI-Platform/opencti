import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import CircularProgress from '@material-ui/core/CircularProgress';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { withStyles } from '@material-ui/core/styles';
import { HexagonMultipleOutline, ShieldSearch } from 'mdi-material-ui';
import { DescriptionOutlined, DeviceHubOutlined } from '@material-ui/icons';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import * as R from 'ramda';
import Chip from '@material-ui/core/Chip';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { resolveLink } from '../../../../utils/Entity';
import StixCoreObjectReportsHorizontalBars from '../../analysis/reports/StixCoreObjectReportsHorizontalBars';
import StixCoreObjectStixCoreRelationshipsCloud from '../stix_core_relationships/StixCoreObjectStixCoreRelationshipsCloud';
import StixDomainObjectGlobalKillChain from './StixDomainObjectGlobalKillChain';
import StixDomainObjectTimeline from './StixDomainObjectTimeline';
import Loader from '../../../../components/Loader';
import { stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import ExportButtons from '../../../../components/ExportButtons';
import Filters, { isUniqFilter } from '../lists/Filters';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
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
    backgroundColor: theme.palette.background.chip,
    marginRight: 10,
  },
});

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
    $type: String
    $fromId: String
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      type: $type
      fromId: $fromId
      toTypes: $toTypes
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

class StixDomainObjectThreatKnowledge extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-stix-domain-object-${props.stixDomainObjectId}`,
    );
    this.state = {
      sortBy: R.propOr('name', 'sortBy', params),
      orderAsc: R.propOr(true, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      viewType: R.propOr('killchain', 'viewType', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-stix-domain-object-${this.props.stixDomainObjectId}`,
      this.state,
    );
  }

  handleChangeViewType(event, type) {
    this.setState(
      {
        viewType: type,
      },
      () => this.saveView(),
    );
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  render() {
    const { viewType, filters } = this.state;
    const {
      t,
      n,
      classes,
      stixDomainObjectId,
      stixDomainObjectType,
      displayObservablesStats,
    } = this.props;
    const link = `${resolveLink(
      stixDomainObjectType,
    )}/${stixDomainObjectId}/knowledge`;
    let toTypes = [];
    if (filters.entity_type && filters.entity_type.length > 0) {
      if (R.filter((o) => o.id === 'all', filters.entity_type).length > 0) {
        toTypes = [];
      } else {
        toTypes = filters.entity_type.map((o) => o.id);
      }
    } else if (viewType === 'timeline') {
      toTypes = [
        'Attack-Pattern',
        'Campaign',
        'Incident',
        'Malware',
        'Tool',
        'Vulnerability',
        'Sector',
        'Organization',
        'Individual',
        'Region',
        'Country',
        'City',
      ];
    } else {
      toTypes = ['Attack-Pattern', 'Malware', 'Tool', 'Vulnerability'];
    }
    const finalFilters = convertFilters(R.dissoc('entity_type', filters));
    const paginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: R.filter(
        (x) => x.toLowerCase() !== stixDomainObjectType,
        toTypes,
      ),
      relationship_type: 'stix-core-relationship',
      filters: finalFilters,
    };
    if (viewType === 'timeline') {
      paginationOptions.orderBy = 'start_time';
      paginationOptions.orderMode = 'desc';
    } else {
      paginationOptions.fromRole = 'uses_from';
    }
    return (
      <div>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              elevation={3}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={stixDomainObjectThreatKnowledgeReportsNumberQuery}
                variables={{
                  objectId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
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
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              elevation={3}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromId: stixDomainObjectId,
                  toTypes: displayObservablesStats
                    ? ['Stix-Cyber-Observable']
                    : 'Indicator',
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
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
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              elevation={3}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
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
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6} style={{ marginBottom: 30 }}>
            <StixCoreObjectReportsHorizontalBars
              stixCoreObjectId={stixDomainObjectId}
              field="created-by.internal_id"
              title={t('Distribution of sources')}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginBottom: 30 }}>
            <StixCoreObjectStixCoreRelationshipsCloud
              stixCoreObjectId={stixDomainObjectId}
              stixCoreObjectType="Stix-Domain-Object"
              relationshipType="stix-core-relationship"
              title={t('Distribution of relations')}
              field="entity_type"
              noDirection={true}
            />
          </Grid>
        </Grid>
        <Tabs
          value={viewType}
          indicatorColor="primary"
          textColor="primary"
          onChange={this.handleChangeViewType.bind(this)}
          style={{ margin: '0 0 20px 0' }}
        >
          <Tab label={t('Global kill chain')} value="killchain" />
          <Tab label={t('Timeline')} value="timeline" />
          <div className={classes.filters}>
            <Filters
              availableFilterKeys={[
                'entity_type',
                'markedBy',
                'createdBy',
                'created_start_date',
                'created_end_date',
              ]}
              handleAddFilter={this.handleAddFilter.bind(this)}
              currentFilters={filters}
              allEntityTypes={true}
            />{' '}
            &nbsp;&nbsp;
            {R.map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {R.map(
                    (o) => (
                      <span key={o.value}>
                        {o.value && o.value.length > 0
                          ? truncate(o.value, 15)
                          : t('No label')}{' '}
                        {R.last(currentFilter[1]).value !== o.value && (
                          <code>OR</code>
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
                    onDelete={this.handleRemoveFilter.bind(
                      this,
                      currentFilter[0],
                    )}
                  />
                  {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, R.toPairs(filters))}
          </div>
        </Tabs>
        <div className={classes.export}>
          <ExportButtons
            domElementId="container"
            name={
              viewType === 'killchain' ? t('Global kill chain') : t('Timeline')
            }
          />
        </div>
        <QueryRenderer
          query={stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery}
          variables={{ first: 500, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              if (viewType === 'killchain') {
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
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

StixDomainObjectThreatKnowledge.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  displayObservablesStats: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectThreatKnowledge);
