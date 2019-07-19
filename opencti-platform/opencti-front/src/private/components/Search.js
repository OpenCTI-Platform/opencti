import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';
import TopBar from './nav/TopBar';
import Loader from '../Loader';
import StixDomainEntitiesLines, {
  stixDomainEntitiesLinesQuery,
} from './common/stix_domain_entities/StixDomainEntitiesLines';
import StixObservableSearchLines, {
  stixObservablesSearchLinesQuery,
} from './stix_observables/StixObservablesSearchLines';

const styles = () => ({
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
});

class Search extends Component {
  render() {
    const {
      t,
      me,
      match: {
        params: { keyword },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} keyword={keyword} />
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ marginBottom: 20 }}
        >
          {t('Search for an entity')}
        </Typography>
        <QueryRenderer
          query={stixDomainEntitiesLinesQuery}
          variables={{
            search: keyword,
            count: 200,
            orderBy: 'created_at',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return <StixDomainEntitiesLines data={props} />;
            }
            return <Loader variant="inside" />;
          }}
        />
        <QueryRenderer
          query={stixObservablesSearchLinesQuery}
          variables={{
            search: keyword,
            count: 200,
            orderBy: 'created_at',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return <StixObservableSearchLines data={props} />;
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(Search);
