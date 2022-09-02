import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import * as R from 'ramda';
import { QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';
import TopBar from './nav/TopBar';
import Loader from '../../components/Loader';
import StixDomainObjectsLines, {
  stixDomainObjectsLinesQuery,
} from './common/stix_domain_objects/StixDomainObjectsLines';
import StixCyberObservableSearchLines, {
  stixCyberObservablesSearchLinesQuery,
} from './observations/stix_cyber_observables/StixCyberObservablesSearchLines';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../utils/ListParameters';
import Filters, { isUniqFilter } from './common/lists/Filters';
import { truncate } from '../../utils/String';

const styles = (theme) => ({
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
  filters: {
    float: 'left',
    margin: '2px 0 0 15px',
  },
  parameters: {
    float: 'left',
    margin: '-3px 0 0 15px',
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 10px 0',
  },
});

const TYPE_SEARCH_SIZE = 200;

class Search extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-search',
    );
    const currentFilters = R.propOr([], 'filters', params);
    this.state = {
      filters: currentFilters,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-search',
      this.state,
    );
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
    const {
      t,
      me,
      classes,
      match: {
        params: { keyword },
      },
    } = this.props;
    const { filters } = this.state;
    let searchWords = '';
    try {
      searchWords = decodeURIComponent(keyword || '');
    } catch (e) {
      // Do nothing
    }
    const finalFilters = convertFilters(filters);
    let displayedFilters = filters;
    if (filters && filters.entity_type && filters.entity_type.length === 9) {
      displayedFilters = {
        entity_type: [{ id: 'Default', value: t('Default scope') }],
      };
    }
    return (
      <div>
        <TopBar me={me || null} keyword={searchWords} />
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ marginBottom: 20, float: 'left' }}
        >
          {t('Search for an entity')}
        </Typography>
        <div className={classes.parameters}>
          <Filters
            availableFilterKeys={[
              'entity_type',
              'markedBy',
              'labelledBy',
              'createdBy',
              'confidence_gt',
              'x_opencti_organization_type',
              'created_start_date',
              'created_end_date',
              'created_at_start_date',
              'created_at_end_date',
            ]}
            handleAddFilter={this.handleAddFilter.bind(this)}
          />
          <div className={classes.filters}>
            {R.map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {R.map(
                    (n) => (
                      <span key={n.value}>
                        {truncate(n.value, 15)}{' '}
                        {R.last(currentFilter[1]).value !== n.value && (
                          <code>OR</code>
                        )}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <span key={currentFilter[0]}>
                  <Chip
                    classes={{ root: classes.filter }}
                    label={
                      <div>
                        <strong>{label}</strong>: {values}
                      </div>
                    }
                    onDelete={this.handleRemoveFilter.bind(
                      this,
                      currentFilter[0],
                    )}
                  />
                  {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, R.toPairs(displayedFilters))}
          </div>
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={stixDomainObjectsLinesQuery}
          variables={{
            search: keyword,
            filters: finalFilters,
            count: TYPE_SEARCH_SIZE,
          }}
          render={({ props }) => {
            if (props) {
              return <StixDomainObjectsLines data={props} />;
            }
            return <Loader variant="inside" />;
          }}
        />
        <QueryRenderer
          query={stixCyberObservablesSearchLinesQuery}
          variables={{
            search: keyword,
            filters: finalFilters,
            count: TYPE_SEARCH_SIZE,
          }}
          render={({ props }) => {
            if (props) {
              return <StixCyberObservableSearchLines data={props} />;
            }
            return <div />;
          }}
        />
      </div>
    );
  }
}

Search.propTypes = {
  keyword: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  me: PropTypes.object,
};

export default R.compose(inject18n, withRouter, withStyles(styles))(Search);
