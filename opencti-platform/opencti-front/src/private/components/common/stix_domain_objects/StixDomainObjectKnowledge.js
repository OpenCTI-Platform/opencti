import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import CircularProgress from '@material-ui/core/CircularProgress';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { withStyles } from '@material-ui/core/styles';
import { AssignmentOutlined, DeviceHubOutlined } from '@material-ui/icons';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { resolveLink } from '../../../../utils/Entity';
import EntityReportsPie from '../../analysis/reports/EntityReportsPie';
import EntityStixCoreRelationshipsDonut from '../stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityStixCoreRelationshipsChart from '../stix_core_relationships/EntityStixCoreRelationshipsChart';
import SimpleEntityStixCoreRelationships from '../stix_core_relationships/SimpleEntityStixCoreRelationships';

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
    float: 'left',
    color: theme.palette.primary.main,
    fontSize: 40,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
  },
  icon: {
    position: 'absolute',
    top: 30,
    right: 20,
  },
  graphContainer: {
    width: '100%',
    margin: '20px 0 0 -30px',
  },
});

const stixDomainObjectKnowledgeReportsNumberQuery = graphql`
  query StixDomainObjectKnowledgeReportsNumberQuery(
    $objectId: String
    $endDate: DateTime
  ) {
    reportsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectKnowledgeStixCoreRelationshipsNumberQuery(
    $type: String
    $fromId: String
    $endDate: DateTime
    $inferred: Boolean
  ) {
    stixCoreRelationshipsNumber(
      type: $type
      fromId: $fromId
      endDate: $endDate
      inferred: $inferred
    ) {
      total
      count
    }
  }
`;

class StixDomainObjectKnowledge extends Component {
  render() {
    const {
      t, classes, stixDomainObjectId, stixDomainObjectType,
    } = this.props;
    const link = `${resolveLink(
      stixDomainObjectType,
    )}/${stixDomainObjectId}/knowledge`;
    return (
      <div>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={stixDomainObjectKnowledgeReportsNumberQuery}
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
                        <div className={classes.number}>{total}</div>
                        <ItemNumberDifference
                          difference={difference}
                          description="last month"
                        />
                        <div className="clearfix" />
                        <div className={classes.title}>
                          {t('Total reports')}
                        </div>
                        <div className={classes.icon}>
                          <AssignmentOutlined
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
          <Grid item={true} xs={6}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                  inferred: false,
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.number}>{total}</div>
                        <ItemNumberDifference
                          difference={difference}
                          description="last month"
                        />
                        <div className="clearfix" />
                        <div className={classes.title}>
                          {t('Total direct relations')}
                        </div>
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
          <Grid item={true} xs={6} style={{ marginBottom: 50 }}>
            <EntityReportsPie entityId={stixDomainObjectId} />
          </Grid>
          <Grid item={true} xs={6} style={{ marginBottom: 50 }}>
            <EntityStixCoreRelationshipsDonut
              entityId={stixDomainObjectId}
              entityType="Stix-Domain-Object"
              relationshipType="stix-core-relationship"
              title={t('Distribution of relations (including inferred)')}
              field="entity_type"
              inferred={true}
            />
          </Grid>
        </Grid>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6} style={{ marginBottom: 50 }}>
            <EntityStixCoreRelationshipsChart
              entityId={stixDomainObjectId}
              title={t('Direct relations creations')}
              field="created_at"
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginBottom: 50 }}>
            <SimpleEntityStixCoreRelationships
              entityId={stixDomainObjectId}
              relationshipType="related-to"
              targetStixDomainObjectTypes={['Stix-Domain-Object']}
              entityLink={link}
            />
          </Grid>
        </Grid>
      </div>
    );
  }
}

StixDomainObjectKnowledge.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectKnowledge);
