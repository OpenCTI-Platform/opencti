/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import InformationSystemDetails from './InformationSystemDetails';
import InformationSystemPopover from './InformationSystemPopover';
import InformationSystemDeletion from './InformationSystemDeletion';
import InformationSystemOverview from './InformationSystemOverview';
import InformationSystemFormCreation from './InformationSystemFormCreation';
import InformationSystemGraphCreation from './InformationSystemGraphCreation';
import InformationSystemEditionContainer from './InformationSystemEditionContainer';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class InformationSystemComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayCreate: '',
      displayEdit: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation(type) {
    this.setState({ displayCreate: type });
  }

  render() {
    const {
      classes,
      history,
      location,
      refreshQuery,
      informationSystem,
    } = this.props;
    return (
      <div className={classes.container}>
        <CyioDomainObjectHeader
          history={history}
          name={informationSystem.system_name}
          cyioDomainObject={informationSystem}
          PopoverComponent={<InformationSystemPopover />}
          goBack='/defender HQ/assets/information_systems'
          OperationsComponent={<InformationSystemDeletion />}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
          handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <InformationSystemOverview
              refreshQuery={refreshQuery}
              informationSystem={informationSystem}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <InformationSystemDetails
              history={history}
              refreshQuery={refreshQuery}
              informationSystem={informationSystem}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={12}>
            <CyioCoreObjectExternalReferences
              externalReferences={informationSystem.links}
              cyioCoreObjectId={informationSystem.id}
              fieldName='links'
              refreshQuery={refreshQuery}
              typename={informationSystem.__typename}
            />
          </Grid>
        </Grid>
        <CyioCoreObjectOrCyioCoreRelationshipNotes
          typename={informationSystem.__typename}
          refreshQuery={refreshQuery}
          fieldName='remarks'
          notes={informationSystem.remarks}
          cyioCoreObjectOrCyioCoreRelationshipId={informationSystem.id}
        />
        <InformationSystemFormCreation
          InfoSystemCreation={this.state.displayCreate === 'form'}
          handleInformationSystemCreation={this.handleOpenNewCreation.bind(this)}
        />
        <InformationSystemGraphCreation
          InfoSystemCreation={this.state.displayCreate === 'graph'}
          handleInformationSystemCreation={this.handleOpenNewCreation.bind(this)}
        />
        <InformationSystemEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          informationSystem={informationSystem}
          refreshQuery={refreshQuery}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </div>
    );
  }
}

InformationSystemComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
};

const InformationSystem = createFragmentContainer(InformationSystemComponent, {
  informationSystem: graphql`
    fragment InformationSystem_information on InformationSystem {
      __typename
      id
      short_name
      system_name
      description
      deployment_model
      cloud_service_model
      identity_assurance_level
      federation_assurance_level
      authenticator_assurance_level
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      links {
        __typename
        id
        external_id     # external id
        source_name     # Title
        description     # description
        url             # URL
        media_type      # Media Type
        entity_type
      }
      remarks {
        __typename
        id
        abstract
        content
        authors
        entity_type
      }
      ...InformationSystemOverview_information
      ...InformationSystemDetails_information
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystem);
