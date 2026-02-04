import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Component } from 'react';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import Drawer from '../../common/drawer/Drawer';
import IndicatorCreation from '../indicators/IndicatorCreation';
import StixCyberObservableAddIndicatorsLines, { stixCyberObservableAddIndicatorsLinesQuery } from './StixCyberObservableAddIndicatorsLines';

const styles = () => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
});

class StixCyberObservableAddIndicators extends Component {
  constructor(props) {
    super(props);
    this.state = { search: '' };
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const {
      t,
      classes,
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
                <div>
                  <StixCyberObservableAddIndicatorsLines
                    stixCyberObservable={stixCyberObservable}
                    stixCyberObservableIndicators={
                      stixCyberObservableIndicators
                    }
                    data={props}
                  />
                  <div className={classes.createButton}>
                    <IndicatorCreation
                      display={open}
                      contextual
                      paginationOptions={paginationOptions}
                    />
                  </div>
                </div>
              );
            }}
          />
        </Drawer>
      </>
    );
  }
}

StixCyberObservableAddIndicators.propTypes = {
  stixCyberObservable: PropTypes.object,
  stixCyberObservableIndicators: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableAddIndicators);
