import { useState } from 'react';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { useFormatter } from '../../../../components/i18n';
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

const StixCyberObservableAddIndicators = (props) => {
  const { t_i18n } = useFormatter();
  const [search, setSearch] = useState('');
  const handleSearch = (keyword) => {
    setSearch(keyword);
  };

  const {

    classes,

    stixCyberObservable,

    stixCyberObservableIndicators,

    open,

    handleClose,

  } = props;
  const paginationOptions = {
    search: search,
    orderBy: 'created_at',
    orderMode: 'desc',
  };
  return (
    <>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add indicators')}
        subHeader={{
          left: [(
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
              key="searchInput"
            />
          )],
        }}
      >
        <QueryRenderer
          query={stixCyberObservableAddIndicatorsLinesQuery}
          variables={{
            search: search,
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
};

StixCyberObservableAddIndicators.propTypes = {
  stixCyberObservable: PropTypes.object,
  stixCyberObservableIndicators: PropTypes.array,
  classes: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
};

export default withStyles(styles)(StixCyberObservableAddIndicators);
