import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { QueryRenderer } from 'react-relay';
import { compose, append, filter } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Button from '@material-ui/core/Button';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { Add, Close } from '@material-ui/icons';
import truncate from '../../../utils/String';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import { externalReferencesLinesSearchQuery } from './ExternalReferencesLines';

const styles = theme => ({
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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing.unit * 2,
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  chip: {
    margin: '5px 5px 0 0',
  },
});

class AddExternalReference extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, externalReferences: [], search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  addExternalReference(externalReference) {
    this.setState({ externalReferences: append(externalReference, this.state.externalReferences) });
  }

  removeExternalReference(externalReference) {
    this.setState({ externalReferences: filter(t => t !== externalReference, this.state.externalReferences) });
  }

  render() {
    const {
      t, classes, entityId, entityExternalReferences,
    } = this.props;
    return (
      <div>
        <IconButton color='secondary' aria-label='Add' onClick={this.handleOpen.bind(this)} classes={{ root: classes.createButton }}>
          <Add fontSize='small'/>
        </IconButton>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={this.handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6'>
              {t('Add external references')}
            </Typography>
          </div>
          <div className={classes.container}>
            <div>
              {this.state.externalReferences.map(externalReference => (
                  <Chip
                    key={externalReference.id}
                    avatar={
                      <Avatar>{externalReference.source_name.substring(0, 1)}</Avatar>
                    }
                    onDelete={this.removeExternalReference.bind(this, externalReference)}
                    label={`${externalReference.source_name} ${externalReference.external_id}`}
                    classes={{ root: classes.chip }}
                  />
              ))}
            </div>
            <QueryRenderer
              environment={environment}
              query={externalReferencesLinesSearchQuery}
              variables={{ search: this.state.search, first: 100 }}
              render={({ props }) => {
                if (props && props.externalReferences) {
                  return (
                    <MenuList>
                      {props.externalReferences.edges.map((externalReferenceNode) => {
                        const externalReference = externalReferenceNode.node;
                        const disabled = this.state.externalReferencesIds.includes(externalReference.id) || entityExternalReferences.includes(externalReference.id);
                        return (
                          <MenuItem
                            key={externalReference.id}
                            classes={{ root: classes.menuItem }}
                            disabled={disabled}
                            divider={true}
                            onClick={this.addExternalReference.bind(this, externalReference)}
                          >
                            <ListItemIcon classes={{ root: this.props.classes.itemIcon }}>
                              <Avatar>{externalReference.source_name.substring(0, 1)}</Avatar>
                            </ListItemIcon>
                            <ListItemText
                              primary={`${externalReference.source_name} ${externalReference.external_id}`}
                              secondary={truncate(externalReference.description !== null && externalReference.description.length > 0 ? externalReference.description : externalReference.url, 120)}
                            />
                          </MenuItem>
                        );
                      })}
                    </MenuList>
                  );
                }
                return (
                  <div> &nbsp; </div>
                );
              }}
            />
            <div className={classes.buttons}>
              <Button variant="contained" onClick={this.handleClose.bind(this)} classes={{ root: classes.button }}>
                {t('Cancel')}
              </Button>
              <Button variant='contained' color='primary' classes={{ root: classes.button }}>
                {t('Add')}
              </Button>
            </div>
          </div>
        </Drawer>
      </div>
    );
  }
}

AddExternalReference.propTypes = {
  entityId: PropTypes.string,
  entityExternalReferences: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AddExternalReference);
