import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, map } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import RegionEdition from './RegionEdition';
import RegionPopover from './RegionPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class RegionComponent extends Component {
  render() {
    const { classes, region } = this.props;
    const countries = map((n) => n.node, region.countries.edges);
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={region}
          isOpenctiAlias={true}
          PopoverComponent={<RegionPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={region} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <LocationMiniMap
              center={
                region.latitude && region.longitude
                  ? [region.latitude, region.longitude]
                  : [48.8566969, 2.3514616]
              }
              countries={countries}
              zoom={region.isSubRegion ? 4 : 3}
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
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={region.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/regions/${region.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={region.id}
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
            <StixCoreObjectExternalReferences stixCoreObjectId={region.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={region.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={region.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RegionEdition regionId={region.id} />
        </Security>
      </div>
    );
  }
}

RegionComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Region = createFragmentContainer(RegionComponent, {
  region: graphql`
    fragment Region_region on Region {
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
      objectMarking {
        edges {
          node {
            id
            definition
            x_opencti_color
          }
        }
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
      countries {
        edges {
          node {
            name
            x_opencti_aliases
          }
        }
      }
      name
      latitude
      longitude
      x_opencti_aliases
      isSubRegion
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Region);
