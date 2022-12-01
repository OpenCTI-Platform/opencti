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
import EntityRoleDetails from './EntityPartyDetails';
import EntitiesPartiesPopover from './EntitiesPartiesPopover';
import EntitiesPartiesDeletion from './EntitiesPartiesDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import PartyEntityEditionContainer from './PartyEntityEditionContainer';
import EntitiesPartiesCreation from './EntitiesPartiesCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityPartyComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
    if(this.state.displayEdit === false){
      this.setState({ radioButtonValue: 'locations' });
    }
  }

  handleOpenNewCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      classes,
      party,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            name={party.name}
            cyioDomainObject={party}
            goBack='/data/entities/parties'
            PopoverComponent={<EntitiesPartiesPopover />}
            OperationsComponent={<EntitiesPartiesDeletion />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityRoleDetails party={party} history={history} refreshQuery={refreshQuery} />
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
                typename={party.__typename}
                externalReferences={party.links}
                fieldName='links'
                cyioCoreObjectId={party?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={party.__typename}
                notes={party.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={party?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesPartiesCreation
          openDataCreation={this.state.openDataCreation}
          handlePartyCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <PartyEntityEditionContainer
          displayEdit={this.state.displayEdit}
          party={party}
          history={history}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityPartyComponent.propTypes = {
  party: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityParty = createFragmentContainer(EntityPartyComponent, {
  party: graphql`
    fragment EntityParty_party on OscalParty {
      __typename
      id
      name
      party_type
      email_addresses
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
      ...EntityPartyDetails_party
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityParty);
