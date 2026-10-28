import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Grid from '@mui/material/Grid';
import { DescriptionOutlined, DeviceHubOutlined } from '@mui/icons-material';
import { HexagonMultipleOutline } from 'mdi-material-ui';
import StixCoreObjectReportsHorizontalBar from '../../analyses/reports/StixCoreObjectReportsHorizontalBar';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import withTheme from '../../../../components/withTheme';
import EntityStixCoreRelationshipsHorizontalBars from '../stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import EntityStixSightingRelationshipsDonut from '../../events/stix_sighting_relationships/EntityStixSightingRelationshipsDonut';
import CardNumber from '../../../../components/common/card/CardNumber';

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

class StixDomainObjectKnowledgeComponent extends Component {
  render() {
    const { t, n, stixDomainObjectId, theme } = this.props;
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          sx={{
            mb: 3,
          }}
        >
          <Grid size={4}>
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
                    <CardNumber
                      label={t('Total reports')}
                      value={n(total)}
                      diffLabel={t('30 days')}
                      diffValue={difference}
                      icon={(
                        <DescriptionOutlined
                          style={{
                            color: theme.palette.text.secondary,
                            opacity: 0.35,
                          }}
                          fontSize="large"
                        />
                      )}
                    />
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Grid>
          <Grid size={4}>
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
                    <CardNumber
                      label={t('Total observables')}
                      value={n(total)}
                      diffLabel={t('30 days')}
                      diffValue={difference}
                      icon={(
                        <HexagonMultipleOutline
                          style={{
                            color: theme.palette.text.secondary,
                            opacity: 0.35,
                          }}
                          fontSize="large"
                        />
                      )}
                    />
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Grid>
          <Grid size={4}>
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
                    <CardNumber
                      label={t('Total relations')}
                      value={n(total)}
                      diffLabel={t('30 days')}
                      diffValue={difference}
                      icon={(
                        <DeviceHubOutlined
                          style={{
                            color: theme.palette.text.secondary,
                            opacity: 0.35,
                          }}
                          fontSize="large"
                        />
                      )}
                    />
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Grid>
        </Grid>
        <StixCoreObjectReportsHorizontalBar
          stixCoreObjectId={stixDomainObjectId}
          field="created-by.internal_id"
          title={t('Distribution of reports')}
        />
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid style={{ height: 350 }} size={6}>
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
          <Grid style={{ height: 350 }} size={6}>
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

StixDomainObjectKnowledgeComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  t: PropTypes.func,
  theme: PropTypes.object,
};

export default inject18n(withTheme(StixDomainObjectKnowledgeComponent));
