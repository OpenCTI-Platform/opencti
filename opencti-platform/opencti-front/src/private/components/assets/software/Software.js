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
import SoftwareDetails from './SoftwareDetails';
import SoftwareEdition from './SoftwareEdition';
import SoftwarePopover from './SoftwarePopover';
import SoftwareDeletion from './SoftwareDeletion';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class SoftwareComponent extends Component {
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
      pathname: '/defender HQ/assets/software',
      openNewCreation: true,
    });
  }

  render() {
    const {
      classes,
      software,
      history,
      location,
      refreshQuery,
    } = this.props;
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <div className={classes.container}>
            <CyioDomainObjectHeader
              history={history}
              name={software.name}
              cyioDomainObject={software}
              PopoverComponent={<SoftwarePopover />}
              goBack='/defender HQ/assets/software'
              OperationsComponent={<SoftwareDeletion />}
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <CyioDomainObjectAssetOverview refreshQuery={refreshQuery} cyioDomainObject={software} />
              </Grid>
              <Grid item={true} xs={6}>
                <SoftwareDetails software={software} history={history}/>
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
              style={{ marginTop: 25 }}
            >
              <Grid item={true} xs={6}>
                <CyioCoreObjectExternalReferences
                  externalReferences={software.external_references}
                  cyioCoreObjectId={software.id}
                  fieldName='external_references'
                  refreshQuery={refreshQuery}
                  typename={software.__typename}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <CyioCoreObjectLatestHistory cyioCoreObjectId={software.id} />
              </Grid>
            </Grid>
            <CyioCoreObjectOrCyioCoreRelationshipNotes
              typename={software.__typename}
              refreshQuery={refreshQuery}
              fieldName='notes'
              notes={software.notes}
              cyioCoreObjectOrCyioCoreRelationshipId={software.id}
            />
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SoftwareEdition softwareId={software.id} />
        </Security> */}
          </div>
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SoftwareEdition
            open={this.state.openEdit}
            softwareId={software.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

SoftwareComponent.propTypes = {
  software: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
};

const Software = createFragmentContainer(SoftwareComponent, {
  software: graphql`
    fragment Software_software on SoftwareAsset {
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
      ...SoftwareDetails_software
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Software);
