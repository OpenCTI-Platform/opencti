import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, dissoc, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
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
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const VIEW_AS_KNOWLEDGE = 'knowledge';

class OrganizationComponent extends Component {
  constructor(props) {
    super(props);

    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-organization-${props.organization.id}`,
    );

    this.state = {
      viewAs: propOr(VIEW_AS_KNOWLEDGE, 'viewAs', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-organization-${this.props.organization.id}`,
      dissoc('filters', this.state),
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const { classes, organization } = this.props;
    const { viewAs } = this.state;

    const lastReportsProps = viewAs === VIEW_AS_KNOWLEDGE
      ? { stixCoreObjectOrStixCoreRelationshipId: organization.id }
      : { authorId: organization.id };

    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={organization}
          isOpenctiAlias={true}
          PopoverComponent={<OrganizationPopover />}
          onViewAs={this.handleChangeViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <StixDomainObjectOverview stixDomainObject={organization} />
          </Grid>
          <Grid item={true} xs={6}>
            <OrganizationDetails organization={organization} />
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
              stixObjectOrStixRelationshipId={organization.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/organizations/${organization.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
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
      ...OrganizationDetails_organization
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Organization);
