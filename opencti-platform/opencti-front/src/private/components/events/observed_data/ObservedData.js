import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ObservedDataDetails from './ObservedDataDetails';
import ObservedDataEdition from './ObservedDataEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import ObservedDataPopover from './ObservedDataPopover';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ObservedDataComponent extends Component {
  render() {
    const { classes, observedData } = this.props;
    return (
      <div className={classes.container}>
        <ContainerHeader
          container={observedData}
          PopoverComponent={<ObservedDataPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={observedData} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ObservedDataDetails observedData={observedData} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={observedData.id}
              stixObjectOrStixRelationshipLink={`/dashboard/events/observed_data/${observedData.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={observedData.id}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences
              stixCoreObjectId={observedData.id}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={observedData.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={observedData.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ObservedDataEdition observedDataId={observedData.id} />
        </Security>
      </div>
    );
  }
}

ObservedDataComponent.propTypes = {
  observedData: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ObservedData = createFragmentContainer(ObservedDataComponent, {
  observedData: graphql`
    fragment ObservedData_observedData on ObservedData {
      id
      standard_id
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creator {
        id
        name
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...ObservedDataDetails_observedData
      ...ContainerHeader_container
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ObservedData);
