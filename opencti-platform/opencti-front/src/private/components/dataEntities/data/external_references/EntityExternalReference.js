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
import EntityExternalReferenceDetails from './EntityExternalReferenceDetails';
import EntitiesExternalReferencesPopover from './EntitiesExternalReferencesPopover';
import EntitiesExternalReferencesDeletion from './EntitiesExternalReferencesDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import TopBarBreadcrumbs from '../../../nav/TopBarBreadcrumbs';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import ExternalReferenceEntityEditionContainer from './ExternalReferenceEntityEditionContainer';
import EntitiesExternalReferencesCreation from './EntitiesExternalReferencesCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityExternalReferenceComponent extends Component {
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
      externalReference,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            cyioDomainObject={externalReference}
            history={history}
            PopoverComponent={<EntitiesExternalReferencesPopover />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            OperationsComponent={<EntitiesExternalReferencesDeletion />}
          />
          <TopBarBreadcrumbs />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityExternalReferenceDetails externalReference={externalReference} history={history} refreshQuery={refreshQuery} />
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
                typename={externalReference.__typename}
                externalReferences={externalReference.links}
                fieldName='links'
                cyioCoreObjectId={externalReference?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={externalReference.__typename}
                notes={externalReference.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={externalReference?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesExternalReferencesCreation
          openDataCreation={this.state.openDataCreation}
          handleRoleCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <ExternalReferenceEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityExternalReferenceComponent.propTypes = {
  externalReference: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityExternalReference = createFragmentContainer(EntityExternalReferenceComponent, {
  externalReference: graphql`
    fragment EntityExternalReference_externalReference on OscalRole {
      __typename
      id
      entity_type
      created
      modified
      role_identifier
      name
      short_name
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
      ...EntityExternalReferenceDetails_externalReference
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityExternalReference);
