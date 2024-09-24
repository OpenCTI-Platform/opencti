import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import SectorsLines, { sectorsLinesQuery } from './sectors/SectorsLines';
import SectorCreation from './sectors/SectorCreation';
import SearchInput from '../../../components/SearchInput';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import withRouter from '../../../utils/compat_router/withRouter';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'sectors';

class Sectors extends Component {
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
    const { t } = this.props;
    return (
      <>
        <Breadcrumbs elements={[{ label: t('Entities') }, { label: t('Sectors'), current: true }]} />
        <div style={{ marginTop: -10 }}>
          <SearchInput
            variant="small"
            onSubmit={this.handleSearch.bind(this)}
            keyword={searchTerm}
            style={{ float: 'left' }}
          />
          <div style={{ float: 'right' }}>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <SectorCreation />
            </Security>
          </div>
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={sectorsLinesQuery}
          variables={{ count: 500 }}
          render={({ props }) => (
            <SectorsLines data={props} keyword={searchTerm} />
          )}
        />
      </>
    );
  }
}

Sectors.propTypes = {
  t: PropTypes.func,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter)(Sectors);
