import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
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
    this.state = {
      viewType: 'killchain',
    };
  }

  handleChangeViewType(event, type) {
    this.setState({
      viewType: type,
    });
  }

  render() {
    const { viewType } = this.state;
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
    if (viewType === 'timeline') {
      toTypes = [
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
    const paginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: filter((x) => x.toLowerCase() !== stixDomainObjectType, toTypes),
      relationship_type: 'stix-core-relationship',
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
        </Tabs>
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

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectThreatKnowledge);
