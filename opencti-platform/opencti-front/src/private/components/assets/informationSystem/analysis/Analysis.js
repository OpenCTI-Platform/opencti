/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import InformationSystemPopover from '../InformationSystemPopover';
import InformationSystemDeletion from '../InformationSystemDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class AnalysisComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayCreate: '',
    };
  }

  handleDisplayEdit(type) {
    this.setState({ displayCreate: type });
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
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            name={informationSystem.name}
            cyioDomainObject={informationSystem}
            PopoverComponent={<InformationSystemPopover />}
            goBack='/defender_hq/assets/information_systems'
            OperationsComponent={<InformationSystemDeletion />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
          />
        </div>
      </>
    );
  }
}

AnalysisComponent.propTypes = {
  informationSystem: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
};

const InformationSystem = createFragmentContainer(AnalysisComponent, {
  informationSystem: graphql`
    fragment Analysis_analysis on InformationSystem {
      __typename
      id
      short_name
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(InformationSystem);
