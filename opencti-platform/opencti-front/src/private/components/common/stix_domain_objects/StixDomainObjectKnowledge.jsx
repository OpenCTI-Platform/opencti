import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import { DescriptionOutlined, DeviceHubOutlined } from '@mui/icons-material';
import { HexagonMultipleOutline } from 'mdi-material-ui';
import StixCoreObjectReportsHorizontalBar from '../../analyses/reports/StixCoreObjectReportsHorizontalBar';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import EntityStixCoreRelationshipsHorizontalBars from '../stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import EntityStixSightingRelationshipsDonut from '../../events/stix_sighting_relationships/EntityStixSightingRelationshipsDonut';

const styles = (theme) => ({
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 4,
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
    borderRadius: 4,
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
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $fromId: [String]
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      relationship_type: $relationship_type
      fromId: $fromId
      toTypes: $toTypes
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

class StixDomainObjectKnowledge extends Component {
  render() {
    const { t, n, classes, stixDomainObjectId } = this.props;
    return (
      <>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
            <Card
              variant="outlined"
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
                        <div className={classes.title}>
                          {t('Total reports')}
                        </div>
                        <div className={classes.number}>{n(total)}</div>
                        <ItemNumberDifference difference={difference} />
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
                  stixDomainObjectKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromOrToId: stixDomainObjectId,
                  elementWithTargetTypes: ['Stix-Cyber-Observable'],
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.title}>
                          {t('Total observables')}
                        </div>
                        <div className={classes.number}>{n(total)}</div>
                        <ItemNumberDifference difference={difference} />
                        <div className={classes.icon}>
                          <HexagonMultipleOutline
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
                  stixDomainObjectKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromOrToId: stixDomainObjectId,
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
                        <ItemNumberDifference difference={difference} />
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
          title={t('Distribution of reports')}
        />
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item={true} xs={6} style={{ height: 350 }}>
            <EntityStixCoreRelationshipsHorizontalBars
              toId={stixDomainObjectId}
              fromTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Malware',
              ]}
              relationshipType="targets"
              title={t('Top 10 threats targeting this entity')}
              field="internal_id"
            />
          </Grid>
          <Grid item={true} xs={6} style={{ height: 350 }}>
            <EntityStixSightingRelationshipsDonut
              entityId={stixDomainObjectId}
              title={t('Sightings distribution')}
              field="entity_type"
              variant="inKnowledge"
            />
          </Grid>
        </Grid>
      </>
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
