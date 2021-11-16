/* eslint-disable */
/* refactor */
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
import { Add, Close } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import Dialog from '@material-ui/core/Dialog';
// eslint-disable-next-line import/no-cycle
import StixCoreObjectNotesCards from './StixCoreObjectNotesCards';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddNotesLines, { addNotesLinesQuery } from './AddNotesLines';
import NoteCreation from './NoteCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '452px',
    width: '750px',
    // backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '24px 24px 32px 24px',
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
    // backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    // padding: '20px 20px 20px 60px',
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

class AddNotes extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const {
      t,
      classes,
      display,
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipNotes,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
        {/* <IconButton
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
          classes={{ root: classes.createButton }}
        >
          <Add fontSize="small" />
        </IconButton> */}
        {/* <Dialog
          open={this.state.open}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
        <NoteCreation
          display={true}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        />
        {/* </Dialog> */}
        {/* <Dialog
          open={this.state.open}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
          {/* <div className={classes.header}> */}
            {/* <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton> */}
            {/* <Typography variant="h6" classes={{ root: classes.title }}>
              {t('New Note')}
            </Typography> */}
            {/* <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div> */}
          {/* </div> */}
          {/* <div className={classes.container}>
            <QueryRenderer
              query={addNotesLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <AddNotesLines
                      stixCoreObjectOrStixCoreRelationshipId={
                        stixCoreObjectOrStixCoreRelationshipId
                      }
                      stixCoreObjectOrStixCoreRelationshipNotes={
                        stixCoreObjectOrStixCoreRelationshipNotes
                      }
                      data={props}
                    />
                  );
                }
                return (
                  <List>
                    {Array.from(Array(20), (e, i) => (
                      <ListItem key={i} divider={true} button={false}>
                        <ListItemIcon>
                          <Skeleton
                            animation="wave"
                            variant="circle"
                            width={30}
                            height={30}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
                              width="90%"
                              height={15}
                              style={{ marginBottom: 10 }}
                            />
                          }
                          secondary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
                              width="90%"
                              height={15}
                            />
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                );
              }}
            />
          </div> */}
        {/* </Dialog> */}
        {/* <NoteCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        /> */}
      </div>
    );
  }
}

AddNotes.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  stixCoreObjectOrStixCoreRelationshipNotes: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  display: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(AddNotes);
