import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Loader from '../../../../components/Loader';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import StixDomainObjectAttackPatternsKillChain, {
  stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
} from './StixDomainObjectAttackPatternsKillChain';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class StixDomainObjectVictimology extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-attack-patterns-${props.stixDomainObjectId}`,
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
      viewMode: propOr('matrix', 'viewMode', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-attack-patterns-${this.props.stixDomainObjectId}`,
      this.state,
    );
  }

  handleChangeView(viewMode) {
    this.setState({ viewMode }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  render() {
    const { viewMode, searchTerm } = this.state;
    const { classes, stixDomainObjectId, entityLink } = this.props;
    const paginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: ['Attack-Pattern'],
      relationship_type: 'uses',
    };
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={
            stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery
          }
          variables={{ first: 500, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <StixDomainObjectAttackPatternsKillChain
                  data={props}
                  entityLink={entityLink}
                  paginationOptions={paginationOptions}
                  stixDomainObjectId={stixDomainObjectId}
                  handleChangeView={this.handleChangeView.bind(this)}
                  handleSearch={this.handleSearch.bind(this)}
                  searchTerm={searchTerm}
                  currentView={viewMode}
                />
              );
            }
            return <Loader withRightPadding={true} />;
          }}
        />
      </div>
    );
  }
}

StixDomainObjectVictimology.propTypes = {
  stixDomainObjectId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimology);
