import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
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
    let searchWords = '';
    try {
      searchWords = decodeURIComponent(keyword);
    } catch (e) {
      // Do nothing
    }
    return (
      <div>
        <TopBar me={me || null} keyword={searchWords} />
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ marginBottom: 20 }}
        >
          {t('Search for an entity')}
        </Typography>
        <QueryRenderer
          query={stixDomainObjectsLinesQuery}
          variables={{
            search: keyword,
            count: 100,
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
            count: 100,
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

export default compose(inject18n, withRouter, withStyles(styles))(Search);
