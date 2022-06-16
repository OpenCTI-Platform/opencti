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
        </div>
        <EntitiesLabelsCreation
          openDataCreation={this.state.openDataCreation}
          handleLabelCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <LabelEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          label={label}
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
    fragment EntityLabel_label on CyioLabel {
      __typename
      id
      name
      color
      description
      ...EntityLabelDetails_label
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityLabel);
