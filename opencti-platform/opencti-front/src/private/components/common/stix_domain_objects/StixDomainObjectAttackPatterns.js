import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import Loader from '../../../../components/Loader';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import StixDomainObjectAttackPatternsKillChain, {
  stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
} from './StixDomainObjectAttackPatternsKillChain';
import { isUniqFilter } from '../lists/Filters';

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
      searchTerm: R.propOr('', 'searchTerm', params),
      viewMode: R.propOr('matrix', 'viewMode', params),
      filters: R.propOr({}, 'filters', params),
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

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  render() {
    const { viewMode, searchTerm, filters } = this.state;
    const {
      classes,
      stixDomainObjectId,
      entityLink,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      elementId: stixDomainObjectId,
      elementWithTargetTypes: ['Attack-Pattern'],
      search: searchTerm,
      filters: finalFilters,
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
                  handleAddFilter={this.handleAddFilter.bind(this)}
                  handleRemoveFilter={this.handleRemoveFilter.bind(this)}
                  filters={filters}
                  searchTerm={searchTerm}
                  currentView={viewMode}
                  defaultStartTime={defaultStartTime}
                  defaultStopTime={defaultStopTime}
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
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimology);
