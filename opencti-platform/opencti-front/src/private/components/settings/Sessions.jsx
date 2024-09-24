import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import AccessesMenu from './AccessesMenu';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import SessionsList, { sessionsListQuery } from './SessionsList';
import SearchInput from '../../../components/SearchInput';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import withRouter from '../../../utils/compat_router/withRouter';
import Breadcrumbs from '../../../components/Breadcrumbs';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  parameters: {
    float: 'left',
    marginTop: -10,
  },
});

const LOCAL_STORAGE_KEY = 'sessions';

class Sessions extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
      openExports: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  render() {
    const { searchTerm } = this.state;
    const { t, classes } = this.props;
    return (
      <div className={classes.container}>
        <AccessesMenu />
        <Breadcrumbs elements={[{ label: t('Settings') }, { label: t('Security') }, { label: t('Sessions'), current: true }]} />
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              onSubmit={this.handleSearch.bind(this)}
              keyword={searchTerm}
            />
          </div>
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={sessionsListQuery}
          render={({ props }) => {
            if (props) {
              return <SessionsList data={props} keyword={searchTerm} />;
            }
            return <div />;
          }}
        />
      </div>
    );
  }
}

Sessions.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Sessions);
