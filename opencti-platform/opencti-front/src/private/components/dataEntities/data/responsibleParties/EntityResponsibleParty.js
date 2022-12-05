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
import EntityResponsiblePartyDetails from './EntityResponsiblePartyDetails';
import EntitiesResponsiblePartiesPopover from './EntitiesResponsiblePartiesPopover';
import EntitiesResponsiblePartiesDeletion from './EntitiesResponsiblePartiesDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import ResponsiblePartyEntityEditionContainer from './ResponsiblePartyEntityEditionContainer';
import EntitiesResponsiblePartiesCreation from './EntitiesResponsiblePartiesCreation';
import RelatedTasks from '../../../riskAssessment/risks/remediations/RelatedTasks';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityResponsiblePartyComponent extends Component {
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
      responsibleParty,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            name={responsibleParty.name}
            cyioDomainObject={responsibleParty}
            goBack='/data/entities/responsible_parties'
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            PopoverComponent={<EntitiesResponsiblePartiesPopover />}
            OperationsComponent={<EntitiesResponsiblePartiesDeletion />}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityResponsiblePartyDetails responsibleParty={responsibleParty} history={history} refreshQuery={refreshQuery} />
            </Grid>
          </Grid>
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 25 }}
          >
            <Grid item={true} xs={12}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={responsibleParty.__typename}
                notes={responsibleParty.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop={30}
                cyioCoreObjectOrCyioCoreRelationshipId={responsibleParty?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesResponsiblePartiesCreation
          openDataCreation={this.state.openDataCreation}
          handleResponsiblePartyCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <ResponsiblePartyEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          refreshQuery={refreshQuery}
          responsibleParty={responsibleParty}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityResponsiblePartyComponent.propTypes = {
  responsibleParty: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityRole = createFragmentContainer(EntityResponsiblePartyComponent, {
  responsibleParty: graphql`
    fragment EntityResponsibleParty_responsibleParty on OscalResponsibleParty {
      __typename
      id
      name
      description
      entity_type
      role {
        id
        entity_type
        role_identifier
      }
      parties {
        id
        entity_type
        name
      }
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      remarks {
        __typename
        id
        entity_type
        abstract
        content
        authors
      }
      ...EntityResponsiblePartyDetails_responsibleParty
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityRole);
