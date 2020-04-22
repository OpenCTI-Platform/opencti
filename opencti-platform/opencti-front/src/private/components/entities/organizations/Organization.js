import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, contains } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import OrganizationOverview from './OrganizationOverview';
import OrganizationDetails from './OrganizationDetails';
import OrganizationEdition from './OrganizationEdition';
import OrganizationPopover from './OrganizationPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityIncidentsChart from '../../threats/incidents/EntityIncidentsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const organizationTypesForAuthorMode = ['vendor', 'csirt', 'partner'];

class OrganizationComponent extends Component {
  render() {
    const { classes, organization } = this.props;
    if (
      contains(organization.organization_class, organizationTypesForAuthorMode)
    ) {
      return (
        <div className={classes.container}>
          <StixDomainEntityHeader
            stixDomainEntity={organization}
            PopoverComponent={<OrganizationPopover />}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={3}>
              <OrganizationOverview organization={organization} />
            </Grid>
            <Grid item={true} xs={3}>
              <OrganizationDetails organization={organization} />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityLastReports authorId={organization.id} />
            </Grid>
          </Grid>
          <StixObjectNotes entityId={organization.id} />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 15 }}
          >
            <Grid item={true} xs={12}>
              <EntityReportsChart authorId={organization.id} />
            </Grid>
          </Grid>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <OrganizationEdition organizationId={organization.id} />
          </Security>
        </div>
      );
    }
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={organization}
          PopoverComponent={<OrganizationPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <OrganizationOverview organization={organization} />
          </Grid>
          <Grid item={true} xs={3}>
            <OrganizationDetails organization={organization} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={organization.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={organization.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={organization.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={organization.id} />
          </Grid>
        </Grid>
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
};

const Organization = createFragmentContainer(OrganizationComponent, {
  organization: graphql`
    fragment Organization_organization on Organization {
      id
      organization_class
      name
      alias
      ...OrganizationOverview_organization
      ...OrganizationDetails_organization
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Organization);
