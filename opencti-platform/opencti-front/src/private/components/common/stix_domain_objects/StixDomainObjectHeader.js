import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose, propOr, filter, append, take,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Slide from '@material-ui/core/Slide';
import { Add, Close, Delete } from '@material-ui/icons';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import { DialogTitle } from '@material-ui/core';
import InputLabel from '@material-ui/core/InputLabel/InputLabel';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select/Select';
import MenuItem from '@material-ui/core/MenuItem';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    float: 'right',
    marginTop: '-5px',
  },
  alias: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 15px 0 10px',
    float: 'right',
  },
  viewAsField: {
    marginTop: -5,
    float: 'left',
  },
  viewAsFieldLabel: {
    margin: '5px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
});

const stixDomainObjectMutation = graphql`
  mutation StixDomainObjectHeaderFieldMutation($id: ID!, $input: EditInput!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        ... on AttackPattern {
          aliases
        }
        ... on Campaign {
          aliases
        }
        ... on CourseOfAction {
          x_opencti_aliases
        }
        ... on Individual {
          x_opencti_aliases
        }
        ... on Organization {
          x_opencti_aliases
        }
        ... on Sector {
          x_opencti_aliases
        }
        ... on Infrastructure {
          aliases
        }
        ... on IntrusionSet {
          aliases
        }
        ... on Position {
          x_opencti_aliases
        }
        ... on City {
          x_opencti_aliases
        }
        ... on Country {
          x_opencti_aliases
        }
        ... on Region {
          x_opencti_aliases
        }
        ... on Malware {
          aliases
        }
        ... on ThreatActor {
          aliases
        }
        ... on Tool {
          aliases
        }
        ... on Incident {
          aliases
        }
      }
    }
  }
`;

class StixDomainObjectHeader extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openAlias: false,
      openAliases: false,
      openAliasesCreate: false,
    };
  }

  handleToggleOpenAliases() {
    this.setState({ openAliases: !this.state.openAliases });
  }

  handleToggleCreateAlias() {
    this.setState({ openAlias: !this.state.openAlias });
  }

  getCurrentAliases() {
    return this.props.isOpenctiAlias
      ? this.props.stixDomainObject.x_opencti_aliases
      : this.props.stixDomainObject.aliases;
  }

  onSubmitCreateAlias(element, data, { resetForm }) {
    const currentAliases = this.getCurrentAliases();
    if (
      (currentAliases === null || !currentAliases.includes(data.new_alias))
      && data.new_alias !== ''
    ) {
      commitMutation({
        mutation: stixDomainObjectMutation,
        variables: {
          id: this.props.stixDomainObject.id,
          input: {
            key: this.props.isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
            value: append(data.new_alias, currentAliases),
          },
        },
        onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The alias has been added')),
      });
    }
    this.setState({ openAlias: false });
    resetForm();
  }

  deleteAlias(alias) {
    const currentAliases = this.getCurrentAliases();
    const aliases = filter((a) => a !== alias, currentAliases);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: this.props.stixDomainObject.id,
        input: {
          key: this.props.isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
          value: aliases,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The alias has been removed')),
    });
  }

  render() {
    const {
      t,
      classes,
      variant,
      stixDomainObject,
      isOpenctiAlias,
      PopoverComponent,
      viewAs,
      onViewAs,
      disablePopover,
    } = this.props;
    const aliases = propOr(
      [],
      isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
      stixDomainObject,
    );
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {stixDomainObject.name}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div className={classes.popover}>
            {React.cloneElement(PopoverComponent, {
              id: stixDomainObject.id,
              disabled: disablePopover,
            })}
          </div>
        </Security>
        {typeof onViewAs === 'function' ? (
          <div>
            <InputLabel classes={{ root: classes.viewAsFieldLabel }}>
              {t('Display as')}
            </InputLabel>
            <FormControl classes={{ root: classes.viewAsField }}>
              <Select
                name="view-as"
                value={viewAs}
                onChange={onViewAs.bind(this)}
                inputProps={{
                  name: 'view-as',
                  id: 'view-as',
                }}
              >
                <MenuItem value="knowledge">{t('Knowledge entity')}</MenuItem>
                <MenuItem value="author">{t('Author')}</MenuItem>
              </Select>
            </FormControl>
          </div>
        ) : (
          ''
        )}
        {variant !== 'noaliases' ? (
          <div className={classes.aliases}>
            {take(5, aliases).map((label) => (label.length > 0 ? (
                <Chip
                  key={label}
                  classes={{ root: classes.alias }}
                  label={label}
                  onDelete={this.deleteAlias.bind(this, label)}
                />
            ) : (
              ''
            )))}
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              {aliases.length > 5 ? (
                <Button
                  color="primary"
                  aria-label="More"
                  onClick={this.handleToggleOpenAliases.bind(this)}
                  style={{ fontSize: 14 }}
                >
                  <DotsHorizontalCircleOutline />
                  &nbsp;&nbsp;{t('More')}
                </Button>
              ) : (
                <IconButton
                  style={{ float: 'left', marginTop: -5 }}
                  color="secondary"
                  aria-label="Alias"
                  onClick={this.handleToggleCreateAlias.bind(this)}
                >
                  {this.state.openAlias ? (
                    <Close fontSize="small" />
                  ) : (
                    <Add fontSize="small" />
                  )}
                </IconButton>
              )}
            </Security>
            <Slide
              direction="left"
              in={this.state.openAlias}
              mountOnEnter={true}
              unmountOnExit={true}
            >
              <div style={{ float: 'left', marginTop: -5 }}>
                <Formik
                  initialValues={{ new_alias: '' }}
                  onSubmit={this.onSubmitCreateAlias.bind(this, 'main')}
                >
                  <Form style={{ float: 'right' }}>
                    <Field
                      component={TextField}
                      name="new_alias"
                      autoFocus={true}
                      placeholder={t('New alias')}
                      className={classes.aliasesInput}
                    />
                  </Form>
                </Formik>
              </div>
            </Slide>
          </div>
        ) : (
          ''
        )}
        <div className="clearfix" />
        <Dialog
          open={this.state.openAliases}
          TransitionComponent={Transition}
          onClose={this.handleToggleOpenAliases.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>
            {t('Entity aliases')}
            <Formik
              initialValues={{ new_alias: '' }}
              onSubmit={this.onSubmitCreateAlias.bind(this, 'dialog')}
            >
              {() => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t('New alias')}
                    className={classes.aliasesInput}
                  />
                </Form>
              )}
            </Formik>
          </DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {propOr(
                [],
                isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
                stixDomainObject,
              ).map((label) => (label.length > 0 ? (
                  <ListItem key={label} disableGutters={true} dense={true}>
                    <ListItemText primary={label} />
                    <ListItemSecondaryAction>
                      <IconButton
                        edge="end"
                        aria-label="delete"
                        onClick={this.deleteAlias.bind(this, label)}
                      >
                        <Delete />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
              ) : (
                ''
              )))}
            </List>
            <div
              style={{
                display: this.state.openAliasesCreate ? 'block' : 'none',
              }}
            >
              <Formik
                initialValues={{ new_alias: '' }}
                onSubmit={this.onSubmitCreateAlias.bind(this, 'dialog')}
              >
                {() => (
                  <Form>
                    <Field
                      component={TextField}
                      name="new_alias"
                      autoFocus={true}
                      fullWidth={true}
                      placeholder={t('New aliases')}
                      className={classes.aliasesInput}
                    />
                  </Form>
                )}
              </Formik>
            </div>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleToggleOpenAliases.bind(this)}
              color="primary"
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixDomainObjectHeader.propTypes = {
  stixDomainObject: PropTypes.object,
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
  disablePopover: PropTypes.bool,
  isOpenctiAlias: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(StixDomainObjectHeader);
