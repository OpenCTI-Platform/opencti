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
import InformationSystemOverview from './InformationSystemOverview';
import InformationSystemDetails from './InformationSystemDetails';
import InformationSystemEdition from './InformationSystemEdition';
import InformationSystemPopover from './InformationSystemPopover';
import InformationSystemDeletion from './InformationSystemDeletion';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

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
      displayEdit: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.props.history.push({
      pathname: '/defender HQ/assets/informationSystem',
      openNewCreation: true,
    });
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
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              history={history}
              name={informationSystem.name}
              cyioDomainObject={informationSystem}
              PopoverComponent={<InformationSystemPopover />}
              goBack='/defender HQ/assets/informationSystem'
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
                  informationSystem={informationSystem}
                  history={history}
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
                  externalReferences={informationSystem.external_references}
                  cyioCoreObjectId={informationSystem.id}
                  fieldName='external_references'
                  refreshQuery={refreshQuery}
                  typename={informationSystem.__typename}
                />
              </Grid>
            </Grid>
            <CyioCoreObjectOrCyioCoreRelationshipNotes
              typename={informationSystem.__typename}
              refreshQuery={refreshQuery}
              fieldName='notes'
              notes={informationSystem.notes}
              cyioCoreObjectOrCyioCoreRelationshipId={informationSystem.id}
            />
          </div>
        ) : (
          <InformationSystemEdition
            open={this.state.openEdit}
            softwareId={informationSystem.id}
            history={history}
          />
        )}
      </>
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
    fragment InformationSystem_information on SoftwareAsset {
      __typename
      id
      name
      asset_id
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      external_references {
        __typename
        id
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      notes {
        __typename
        id
        # created
        # modified
        entity_type
        abstract
        content
        authors
      }
      description
      version
      vendor_name
      patch_level
      asset_tag
      asset_type
      serial_number
      release_date
      operational_status
      ...InformationSystemOverview_information
      ...InformationSystemDetails_information
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystem);
