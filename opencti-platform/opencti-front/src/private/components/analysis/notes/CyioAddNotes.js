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
import Dialog from '@material-ui/core/Dialog';
import Button from '@material-ui/core/Button';
import InputAdornment from '@material-ui/core/InputAdornment';
import CardActions from '@material-ui/core/CardActions';
import TextField from '@material-ui/core/TextField';
import Collapse from '@material-ui/core/Collapse';
import Divider from '@material-ui/core/Divider';
import DialogTitle from '@material-ui/core/DialogTitle';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { Add, Close } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import { QueryRenderer as QR } from 'react-relay';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import AddNotesLines, { addNotesLinesQuery } from './AddNotesLines';
import NoteCreation from './NoteCreation';
import CyioNoteCreation from './CyioNoteCreation';
import CyioAddNotesLines, { cyioAddNotesLinesQuery } from './CyioAddNotesLines';

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
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
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
  collapse: {
    width: '70%',
    maxHeight: '344px',
    overflowY: 'scroll',
    background: theme.palette.background.paper,
  },
  dialogMain: {
    padding: '24px',
    background: theme.palette.background.paper,
  },
});

class CyioAddNotes extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      search: '',
      expanded: false,
  };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(event) {
    const keyword = event.target.value;
    this.setState({ search: keyword, expanded: keyword ? true : false });
    // this.setState({ search: keyword });
  }

  render() {
    const {
      t,
      classes,
      cyioCoreObjectOrStixCoreRelationshipId,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
        <IconButton
          color="secondary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
          classes={{ root: classes.createButton }}
        >
          <Add fontSize="small" />
        </IconButton>
        <div classes={{ root: classes.dialogRoot }}>
          <Dialog
            maxWidth='md'
            open={this.state.open}
            onClose={this.handleClose.bind(this)}
            timeout="auto"
            unmountOnExit
            PaperProps={{
              style: {
                backgroundColor: 'transparent',
                boxShadow: 'none',
                borderRadius: '0px',
                overflowY: 'hidden',
              },
            }}
          >
            <div className={classes.dialogMain}>
              <DialogTitle style={{ padding: 10 }}>{t('Add Notes')}</DialogTitle>
              {/* <CardHeader title="Add External Refrences"/> */}
              <CardActions sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <TextField
                  style={{ width: 495 }}
                  onChange={this.handleSearch.bind(this)}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end" >
                        <CyioNoteCreation
                          display={true}
                          contextual={true}
                          inputValue={this.state.search}
                          paginationOptions={paginationOptions}
                          // onCreate={this.toggleNotes.bind(this)}
                        />
                      </InputAdornment>
                    ),
                  }} />
                <div style={{ float: 'right', marginLeft: '40px' }}>
                  <Button style={{ marginLeft: '10px', marginRight: '10px' }} onClick={this.handleClose.bind(this)} variant="outlined" >{t('Cancel')}</Button>
                  <Button variant="contained" color="primary">{t('Add')}</Button>
                </div>
                <Divider light={true} />
              </CardActions>
            </div>
            <Collapse sx={{ maxWidth: '500px', borderRadius: 0 }} in={this.state.expanded} timeout="auto" unmountOnExit>
              <div className={classes.collapse}>
                <QR
                  environment={QueryRendererDarkLight}
                  query={cyioAddNotesLinesQuery}
                  variables={{
                    search: this.state.search,
                    count: 4,
                  }}
                  render={({ props }) => {
                    if (props) {
                      return (
                        <CyioAddNotesLines
                          cyioCoreObjectOrStixCoreRelationshipId={
                            cyioCoreObjectOrStixCoreRelationshipId
                          }
                          cyioCoreObjectOrStixCoreRelationshipNotes={
                            cyioCoreObjectOrStixCoreRelationshipNotes
                          }
                          data={props}
                          open={this.state.open}
                          search={this.state.search}
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
              </div>
            </Collapse>
          </Dialog>
        </div>
      </div>
    );
  }
}

CyioAddNotes.propTypes = {
  cyioCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrStixCoreRelationshipNotes: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(CyioAddNotes);
