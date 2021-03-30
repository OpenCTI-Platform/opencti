import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import IndividualPopover from './IndividualPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

const VIEW_AS_KNOWLEDGE = 'knowledge';

class IndividualAnalysisComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-individual-${props.individual.id}`,
    );
    this.state = {
      viewAs: propOr(VIEW_AS_KNOWLEDGE, 'viewAs', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-individual-${this.props.individual.id}`,
      this.state,
      true,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const { classes, individual } = this.props;
    const { viewAs } = this.state;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={individual}
          PopoverComponent={<IndividualPopover />}
          onViewAs={this.handleChangeViewAs.bind(this)}
          viewAs={viewAs}
        />
        {viewAs === VIEW_AS_KNOWLEDGE ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixCoreObjectOrStixCoreRelationshipId={individual.id}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            authorId={individual.id}
            viewAs={viewAs}
          />
        )}
      </div>
    );
  }
}

IndividualAnalysisComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IndividualAnalysis = createFragmentContainer(
  IndividualAnalysisComponent,
  {
    individual: graphql`
      fragment IndividualAnalysis_individual on Individual {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IndividualAnalysis);
