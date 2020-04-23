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
import {
  Add, Close, Delete, More,
} from '@material-ui/icons';
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
  aliasInput: {
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

const stixDomainEntityMutation = graphql`
  mutation StixDomainEntityHeaderFieldMutation($id: ID!, $input: EditInput!) {
    stixDomainEntityEdit(id: $id) {
      fieldPatch(input: $input) {
        alias
      }
    }
  }
`;

class StixDomainEntityHeader extends Component {
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

  onSubmitCreateAlias(element, data, { resetForm }) {
    if (
      (this.props.stixDomainEntity.alias === null
        || !this.props.stixDomainEntity.alias.includes(data.new_alias))
      && data.new_alias !== ''
    ) {
      commitMutation({
        mutation: stixDomainEntityMutation,
        variables: {
          id: this.props.stixDomainEntity.id,
          input: {
            key: 'alias',
            value: append(data.new_alias, this.props.stixDomainEntity.alias),
          },
        },
        onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The alias has been added')),
      });
    }
    this.setState({ openAlias: false });
    resetForm();
  }

  deleteAlias(alias) {
    const aliases = filter(
      (a) => a !== alias,
      this.props.stixDomainEntity.alias,
    );
    commitMutation({
      mutation: stixDomainEntityMutation,
      variables: {
        id: this.props.stixDomainEntity.id,
        input: { key: 'alias', value: aliases },
      },
    });
  }

  render() {
    const {
      t,
      classes,
      variant,
      stixDomainEntity,
      PopoverComponent,
      viewAs,
      onViewAs,
      disablePopover,
    } = this.props;
    const alias = propOr([], 'alias', stixDomainEntity);
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {stixDomainEntity.name}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div className={classes.popover}>
            {React.cloneElement(PopoverComponent, {
              id: stixDomainEntity.id,
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
        {variant !== 'noalias' ? (
          <div className={classes.aliases}>
            {take(5, alias).map((label) => (label.length > 0 ? (
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
              {alias.length > 5 ? (
                <IconButton
                  color="primary"
                  aria-label="More"
                  onClick={this.handleToggleOpenAliases.bind(this)}
                >
                  <More fontSize="small" />
                </IconButton>
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
                      className={classes.aliasInput}
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
                    className={classes.aliasInput}
                  />
                </Form>
              )}
            </Formik>
          </DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {propOr([], 'alias', stixDomainEntity).map((label) => (label.length > 0 ? (
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
                      placeholder={t('New alias')}
                      className={classes.aliasInput}
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

StixDomainEntityHeader.propTypes = {
  stixDomainEntity: PropTypes.object,
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
  disablePopover: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(StixDomainEntityHeader);
