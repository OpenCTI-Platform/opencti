/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import EntityLocationDetails from './EntityLocationDetails';
import EntitiesLocationsPopover from './EntitiesLocationsPopover';
import EntitiesLocationsDeletion from './EntitiesLocationsDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import TopBarBreadcrumbs from '../../../nav/TopBarBreadcrumbs';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import RoleEntityEditionContainer from './LocationEntityEditionContainer';
import EntitiesLocationsCreation from './EntitiesLocationsCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EmtityLocationComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      classes,
      location,
      history,
      refreshQuery,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            cyioDomainObject={location}
            history={history}
            PopoverComponent={<EntitiesLocationsPopover />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            OperationsComponent={<EntitiesLocationsDeletion />}
          />
          <TopBarBreadcrumbs />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityLocationDetails location={location} history={history} refreshQuery={refreshQuery} />
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
                typename={location.__typename}
                externalReferences={location.links}
                fieldName='links'
                cyioCoreObjectId={location?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={location.__typename}
                notes={location.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={location?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesLocationsCreation
          openDataCreation={this.state.openDataCreation}
          handleRoleCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <RoleEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EmtityLocationComponent.propTypes = {
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityLocation = createFragmentContainer(EmtityLocationComponent, {
  location: graphql`
    fragment EntityLocation_location on OscalLocation {
      __typename
      id
      created
      modified
      name
      description
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
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      remarks {
        __typename
        id
        entity_type
        abstract
        content
        authors
      }
      ...EntityLocationDetails_location
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityLocation);
