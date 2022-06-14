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
import EntityLabelDetails from './EntityLabelDetails';
import EntitiesLabelsPopover from './EntitiesLabelsPopover';
import EntitiesLabelsDeletion from './EntitiesLabelsDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import TopBarBreadcrumbs from '../../../nav/TopBarBreadcrumbs';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import LabelEntityEditionContainer from './LabelEntityEditionContainer';
import EntitiesLabelsCreation from './EntitiesLabelsCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EmtityLabelComponent extends Component {
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
      label,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            cyioDomainObject={label}
            history={history}
            PopoverComponent={<EntitiesLabelsPopover />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            OperationsComponent={<EntitiesLabelsDeletion />}
          />
          <TopBarBreadcrumbs />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityLabelDetails label={label} history={history} refreshQuery={refreshQuery} />
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
                typename={label.__typename}
                externalReferences={label.links}
                fieldName='links'
                cyioCoreObjectId={label?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={label.__typename}
                notes={label.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={label?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesLabelsCreation
          openDataCreation={this.state.openDataCreation}
          handleLabelCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <LabelEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EmtityLabelComponent.propTypes = {
  label: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityLabel = createFragmentContainer(EmtityLabelComponent, {
  label: graphql`
    fragment EntityLabel_label on OscalRole {
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
      ...EntityLabelDetails_label
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityLabel);
