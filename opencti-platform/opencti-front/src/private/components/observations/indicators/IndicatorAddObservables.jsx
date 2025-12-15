import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { Add, Close } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import IndicatorAddObservablesLines, { indicatorAddObservablesLinesQuery } from './IndicatorAddObservablesLines';
import StixCyberObservableCreation from '../stix_cyber_observables/StixCyberObservableCreation';

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

class IndicatorAddObservables extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const { t, classes, indicator, indicatorObservables } = this.props;
    const paginationOptions = {
      search: this.state.search,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          keepMounted={true}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add observables')}
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
              query={indicatorAddObservablesLinesQuery}
              variables={{
                search: this.state.search,
                orderBy: 'created_at',
                orderMode: 'desc',
                count: 50,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <IndicatorAddObservablesLines
                      indicator={indicator}
                      indicatorObservables={indicatorObservables}
                      data={props}
                    />
                  );
                }
                return (
                  <List>
                    {Array.from(Array(20), (e, i) => (
                      <ListItem key={i} divider={true}>
                        <ListItemIcon>
                          <Skeleton
                            animation="wave"
                            variant="circular"
                            width={30}
                            height={30}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={(
                            <Skeleton
                              animation="wave"
                              variant="rectangular"
                              width="90%"
                              height={15}
                              style={{ marginBottom: 10 }}
                            />
                          )}
                          secondary={(
                            <Skeleton
                              animation="wave"
                              variant="rectangular"
                              width="90%"
                              height={15}
                            />
                          )}
                        />
                      </ListItem>
                    ))}
                  </List>
                );
              }}
            />
          </div>
        </Drawer>
        <StixCyberObservableCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationKey="Pagination_stixCyberObservables"
          paginationOptions={paginationOptions}
        />
      </>
    );
  }
}

IndicatorAddObservables.propTypes = {
  indicator: PropTypes.object,
  indicatorObservables: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(IndicatorAddObservables);
