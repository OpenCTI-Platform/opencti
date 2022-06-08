import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import CountryEdition from './CountryEdition';
import CountryPopover from './CountryPopover';
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

class CountryComponent extends Component {
  render() {
    const { classes, country } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={country}
          isOpenctiAlias={true}
          PopoverComponent={<CountryPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={country} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <LocationMiniMap
              center={
                country.latitude && country.longitude
                  ? [country.latitude, country.longitude]
                  : [48.8566969, 2.3514616]
              }
              countries={[country]}
              zoom={4}
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
              stixObjectOrStixRelationshipId={country.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/countries/${country.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={country.id}
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
            <StixCoreObjectExternalReferences stixCoreObjectId={country.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={country.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={country.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CountryEdition countryId={country.id} />
        </Security>
      </div>
    );
  }
}

CountryComponent.propTypes = {
  country: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Country = createFragmentContainer(CountryComponent, {
  country: graphql`
    fragment Country_country on Country {
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
      name
      latitude
      longitude
      x_opencti_aliases
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

export default compose(inject18n, withStyles(styles))(Country);
