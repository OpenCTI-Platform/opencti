import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import NarrativesLines, { narrativesLinesQuery } from './narratives/NarrativesLines';
import NarrativeCreation from './narratives/NarrativeCreation';
import SearchInput from '../../../components/SearchInput';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import withRouter from '../../../utils/compat-router/withRouter';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'narratives';

const styles = () => ({
  parameters: {
    width: '100%',
    marginTop: -10,
  },
});

class Narratives extends Component {
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

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  render() {
    const { searchTerm } = this.state;
    const { t, classes } = this.props;
    return (
      <>
        <Breadcrumbs variant="list" elements={[{ label: t('Techniques') }, { label: t('Narratives'), current: true }]} />
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              onSubmit={this.handleSearch.bind(this)}
              keyword={searchTerm}
            />
          </div>
          <div style={{ float: 'right' }}>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <NarrativeCreation />
            </Security>
          </div>
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={narrativesLinesQuery}
          variables={{ count: 500 }}
          render={({ props }) => (
            <NarrativesLines data={props} keyword={searchTerm} />
          )}
        />
      </>
    );
  }
}

Narratives.propTypes = {
  t: PropTypes.func,
  navigate: PropTypes.func,
  location: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Narratives);
