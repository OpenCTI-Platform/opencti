import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { Add, Close } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddOpinionsLines, { addOpinionsLinesQuery } from './AddOpinionsLines';
import OpinionCreation from './OpinionCreation';

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

class AddOpinions extends Component {
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
    const { t, classes, entityId, entityOpinions } = this.props;
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
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add opinions')}
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
              query={addOpinionsLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <AddOpinionsLines
                      entityId={entityId}
                      entityOpinions={entityOpinions}
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
                            variant="circular"
                            width={30}
                            height={30}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Skeleton
                              animation="wave"
                              variant="rectangular"
                              width="90%"
                              height={15}
                              style={{ marginBottom: 10 }}
                            />
                          }
                          secondary={
                            <Skeleton
                              animation="wave"
                              variant="rectangular"
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
        </Drawer>
        <OpinionCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

AddOpinions.propTypes = {
  entityId: PropTypes.string,
  entityOpinions: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(AddOpinions);
