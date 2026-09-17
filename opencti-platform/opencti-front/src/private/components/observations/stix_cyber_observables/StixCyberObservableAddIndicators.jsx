import Button from '@common/button/Button';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Component } from 'react';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import Drawer from '../../common/drawer/Drawer';
import IndicatorCreation from '../indicators/IndicatorCreation';
import StixCyberObservableAddIndicatorsLines, { stixCyberObservableAddIndicatorsLinesQuery } from './StixCyberObservableAddIndicatorsLines';

class StixCyberObservableAddIndicators extends Component {
  constructor(props) {
    super(props);
    this.state = { search: '', indicatorCreation: false, creationKey: 0 };
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const {
      t,
      stixCyberObservable,
      stixCyberObservableIndicators,
      open,
      handleClose,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <>
        <Drawer
          open={open}
          onClose={handleClose.bind(this)}
          title={t('Add indicators')}
          subHeader={{
            left: [(
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
                key="searchInput"
              />
            )],
            right: [(
              <Button
                key="createIndicator"
                aria-label={t('Create an indicator')}
                onClick={() => this.setState({ indicatorCreation: true })}
              >
                {t('Create an indicator')}
              </Button>
            )],
          }}
        >
          <QueryRenderer
            query={stixCyberObservableAddIndicatorsLinesQuery}
            variables={{
              search: this.state.search,
              orderBy: 'created_at',
              orderMode: 'desc',
              count: 50,
            }}
            render={({ props }) => {
              return (
                <StixCyberObservableAddIndicatorsLines
                  stixCyberObservable={stixCyberObservable}
                  stixCyberObservableIndicators={stixCyberObservableIndicators}
                  data={props}
                />
              );
            }}
          />
        </Drawer>
        <IndicatorCreation
          display={false}
          contextual
          speeddial
          // Remount on close, as in IndicatorAddObservables: the host-driven
          // close does not reset what the dialog's own one resets.
          key={this.state.creationKey}
          open={this.state.indicatorCreation}
          handleClose={() => this.setState(({ creationKey }) => ({
            indicatorCreation: false,
            creationKey: creationKey + 1,
          }))}
          paginationOptions={paginationOptions}
        />
      </>
    );
  }
}

StixCyberObservableAddIndicators.propTypes = {
  stixCyberObservable: PropTypes.object,
  stixCyberObservableIndicators: PropTypes.array,
  t: PropTypes.func,
  fld: PropTypes.func,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
};

export default compose(inject18n)(StixCyberObservableAddIndicators);
