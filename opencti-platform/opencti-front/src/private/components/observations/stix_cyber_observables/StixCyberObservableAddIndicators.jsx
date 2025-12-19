import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@common/button/IconButton';
import Typography from '@mui/material/Typography';
import { Close } from '@mui/icons-material';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import StixCyberObservableAddIndicatorsLines, { stixCyberObservableAddIndicatorsLinesQuery } from './StixCyberObservableAddIndicatorsLines';
import IndicatorCreation from '../indicators/IndicatorCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
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
          keepMounted={true}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleClose.bind(this)}
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add indicators')}
            </Typography>
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.container}>
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
                    stixCyberObservableIndicators={
                      stixCyberObservableIndicators
                    }
                    data={props}
                  />
                );
              }}
            />
          </div>
          <div className={classes.createButton}>
            <IndicatorCreation
              display={open}
              contextual
              paginationOptions={paginationOptions}
            />
          </div>
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
