import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import OrganizationDetails from './OrganizationDetails';
import OrganizationEdition from './OrganizationEdition';
import OrganizationPopover from './OrganizationPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class OrganizationComponent extends Component {
  render() {
    const { classes, organization, viewAs, onViewAs } = this.props;
    const lastReportsProps = viewAs === 'knowledge'
      ? { stixCoreObjectOrStixCoreRelationshipId: organization.id }
      : { authorId: organization.id };
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={organization}
          isOpenctiAlias={true}
          PopoverComponent={<OrganizationPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={organization} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <OrganizationDetails organization={organization} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          {viewAs === 'knowledge' && (
            <Grid item={true} xs={6}>
              <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                stixObjectOrStixRelationshipId={organization.id}
                stixObjectOrStixRelationshipLink={`/dashboard/entities/organizations/${organization.id}/knowledge`}
              />
            </Grid>
          )}
          <Grid item={true} xs={viewAs === 'knowledge' ? 6 : 12}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              {...lastReportsProps}
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
              stixCoreObjectId={organization.id}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={organization.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={organization.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <OrganizationEdition organizationId={organization.id} />
        </Security>
      </div>
    );
  }
}

OrganizationComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
};

const Organization = createFragmentContainer(OrganizationComponent, {
  organization: graphql`
    fragment Organization_organization on Organization {
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
      ...OrganizationDetails_organization
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Organization);
