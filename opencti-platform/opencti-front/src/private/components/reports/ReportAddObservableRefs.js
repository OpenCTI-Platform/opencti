import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import Avatar from '@material-ui/core/Avatar';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import ReportAddObservableRefsLines, {
  reportAddObservableRefsLinesQuery,
} from './ReportAddObservableRefsLines';
import StixObservableCreation from '../signatures/stix_observables/StixObservableCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    zIndex: 1100,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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

class ReportAddObservableRefs extends Component {
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
    const { t, classes, reportId } = this.props;
    const paginationOptions = {
      search: this.state.search,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          keepMounted={true}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add observables')}
            </Typography>
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.container}>
            <QueryRenderer
              query={reportAddObservableRefsLinesQuery}
              variables={{ count: 50, ...paginationOptions }}
              render={({ props }) => {
                if (props) {
                  return (
                    <ReportAddObservableRefsLines
                      reportId={reportId}
                      data={props}
                      paginationOptions={this.props.paginationOptions}
                    />
                  );
                }
                return (
                  <List>
                    {Array.from(Array(20), (e, i) => (
                      <ListItem key={i} divider={true} button={false}>
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatar }}>
                            {i}
                          </Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <span
                              className="fakeItem"
                              style={{ width: '80%' }}
                            />
                          }
                          secondary={
                            <span
                              className="fakeItem"
                              style={{ width: '90%' }}
                            />
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                );
              }}
            />
          </div>
        </Drawer>
        <StixObservableCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

ReportAddObservableRefs.propTypes = {
  reportId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(ReportAddObservableRefs);
