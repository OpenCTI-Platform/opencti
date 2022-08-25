import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import { Add, Close, Delete } from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import { DialogTitle } from '@mui/material';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import * as Yup from 'yup';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';
import CommitMessage from '../form/CommitMessage';

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
    marginTop: -6,
    float: 'left',
  },
  viewAsFieldLabel: {
    margin: '2px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
});

export const stixDomainObjectMutation = graphql`
  mutation StixDomainObjectHeaderFieldMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        x_opencti_stix_ids
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
        ... on System {
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
        ... on Channel {
          aliases
        }
        ... on Event {
          aliases
        }
        ... on Narrative {
          aliases
        }
        ... on Language {
          aliases
        }
        ... on Incident {
          aliases
        }
        ... on Vulnerability {
          x_opencti_aliases
        }
      }
    }
  }
`;

const aliasValidation = (t) => Yup.object().shape({
  references: Yup.array().required(t('This field is required')),
});

class StixDomainObjectHeader extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openAlias: false,
      openAliases: false,
      openAliasesCreate: false,
      openCommitCreate: false,
      openCommitDelete: false,
      newAlias: '',
      aliasToDelete: null,
    };
  }

  handleToggleOpenAliases() {
    this.setState({ openAliases: !this.state.openAliases });
  }

  handleToggleCreateAlias() {
    this.setState({ openAlias: !this.state.openAlias });
  }

  handleOpenCommitCreate() {
    this.setState({ openCommitCreate: true });
  }

  handleCloseCommitCreate() {
    this.setState({ openCommitCreate: false });
  }

  handleOpenCommitDelete(label) {
    this.setState({ openCommitDelete: true, aliasToDelete: label });
  }

  handleCloseCommitDelete() {
    this.setState({ openCommitDelete: false });
  }

  handleChangeNewAlias(name, value) {
    this.setState({ newAlias: value });
  }

  getCurrentAliases() {
    return this.props.isOpenctiAlias
      ? this.props.stixDomainObject.x_opencti_aliases
      : this.props.stixDomainObject.aliases;
  }

  onSubmitCreateAlias(element, data, { resetForm, setSubmitting }) {
    const currentAliases = this.getCurrentAliases();
    const { newAlias } = this.state;
    if (
      (currentAliases === null || !currentAliases.includes(newAlias))
      && newAlias !== ''
    ) {
      commitMutation({
        mutation: stixDomainObjectMutation,
        variables: {
          id: this.props.stixDomainObject.id,
          input: {
            key: this.props.isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
            value: R.append(newAlias, currentAliases),
          },
          commitMessage: data.message,
          references: R.pluck('value', data.references || []),
        },
        setSubmitting,
        onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The alias has been added')),
      });
    }
    this.setState({ openAlias: false, openCommitCreate: false, newAlias: '' });
    resetForm();
  }

  deleteAlias(alias, data = {}) {
    const currentAliases = this.getCurrentAliases();
    const aliases = R.filter((a) => a !== alias, currentAliases);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: this.props.stixDomainObject.id,
        input: {
          key: this.props.isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
          value: aliases,
        },
        commitMessage: data.message,
        references: R.pluck('value', data.references || []),
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The alias has been removed')),
    });
    this.setState({ openCommitDelete: false });
  }

  onSubmitDeleteAlias(data, { resetForm }) {
    const { aliasToDelete } = this.state;
    this.deleteAlias(aliasToDelete, data);
    this.setState({ openCommitDelete: false, aliasToDelete: null });
    resetForm();
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
      enableReferences,
    } = this.props;
    const aliases = R.propOr(
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
        {typeof onViewAs === 'function' && (
          <div>
            <InputLabel classes={{ root: classes.viewAsFieldLabel }}>
              {t('Display as')}
            </InputLabel>
            <FormControl classes={{ root: classes.viewAsField }}>
              <Select
                size="small"
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
        )}
        <StixCoreObjectEnrichment stixCoreObjectId={stixDomainObject.id} />
        {variant !== 'noaliases' && (
          <div className={classes.aliases}>
            {R.take(5, aliases).map(
              (label) => label.length > 0 && (
                  <Security
                    needs={[KNOWLEDGE_KNUPDATE]}
                    key={label}
                    placeholder={
                      <Chip classes={{ root: classes.alias }} label={label} />
                    }
                  >
                    <Chip
                      classes={{ root: classes.alias }}
                      label={label}
                      onDelete={
                        enableReferences
                          ? this.handleOpenCommitDelete.bind(this, label)
                          : this.deleteAlias.bind(this, label)
                      }
                    />
                  </Security>
              ),
            )}
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
                  size="large"
                >
                  {this.state.openAlias ? (
                    <Close fontSize="small" color="primary" />
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
                  validationSchema={
                    enableReferences ? aliasValidation(t) : null
                  }
                >
                  {({
                    submitForm,
                    isSubmitting,
                    validateForm,
                    setFieldValue,
                    values,
                  }) => (
                    <Form style={{ float: 'right' }}>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="new_alias"
                        autoFocus={true}
                        placeholder={t('New alias')}
                        className={classes.aliasesInput}
                        onChange={this.handleChangeNewAlias.bind(this)}
                        value={this.state.newAlias}
                        onKeyDown={(e) => {
                          if (e.keyCode === 13) {
                            if (
                              enableReferences
                              && !this.state.openCommitCreate
                            ) {
                              return this.handleOpenCommitCreate();
                            }
                            return submitForm();
                          }
                          return true;
                        }}
                      />
                      {enableReferences && (
                        <CommitMessage
                          handleClose={this.openCommitCreate.bind(this)}
                          open={this.state.openCommitCreate}
                          submitForm={submitForm}
                          disabled={isSubmitting}
                          validateForm={validateForm}
                          setFieldValue={setFieldValue}
                          values={values}
                          id={stixDomainObject.id}
                        />
                      )}
                    </Form>
                  )}
                </Formik>
              </div>
            </Slide>
          </div>
        )}
        <div className="clearfix" />
        <Dialog
          PaperProps={{ elevation: 1 }}
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
              validationSchema={enableReferences ? aliasValidation(t) : null}
            >
              {({
                submitForm,
                isSubmitting,
                validateForm,
                setFieldValue,
                values,
              }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_alias"
                    autoFocus={true}
                    placeholder={t('New alias')}
                    className={classes.aliasesInput}
                    onChange={this.handleChangeNewAlias.bind(this)}
                    value={this.state.newAlias}
                    onKeyDown={(e) => {
                      if (e.keyCode === 13) {
                        if (enableReferences) {
                          return this.handleOpenCommitCreate();
                        }
                        return submitForm();
                      }
                      return true;
                    }}
                  />
                  {enableReferences && (
                    <CommitMessage
                      handleClose={this.handleCloseCommitCreate.bind(this)}
                      open={this.state.openCommitCreate}
                      submitForm={submitForm}
                      disabled={isSubmitting}
                      validateForm={validateForm}
                      setFieldValue={setFieldValue}
                      values={values}
                      id={stixDomainObject.id}
                    />
                  )}
                </Form>
              )}
            </Formik>
          </DialogTitle>
          <DialogContent dividers={true}>
            <List>
              {R.propOr(
                [],
                isOpenctiAlias ? 'x_opencti_aliases' : 'aliases',
                stixDomainObject,
              ).map(
                (label) => label.length > 0 && (
                    <ListItem key={label} disableGutters={true} dense={true}>
                      <ListItemText primary={label} />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          aria-label="delete"
                          onClick={
                            enableReferences
                              ? this.handleOpenCommitDelete.bind(this, label)
                              : this.deleteAlias.bind(this, label)
                          }
                          size="large"
                        >
                          <Delete />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                ),
              )}
            </List>
            <div
              style={{
                display: this.state.openAliasesCreate ? 'block' : 'none',
              }}
            >
              <Formik
                initialValues={{ new_alias: '' }}
                onSubmit={this.onSubmitCreateAlias.bind(this, 'dialog')}
                validationSchema={enableReferences ? aliasValidation(t) : null}
              >
                {({
                  submitForm,
                  isSubmitting,
                  validateForm,
                  setFieldValue,
                  values,
                }) => (
                  <Form>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="new_alias"
                      autoFocus={true}
                      fullWidth={true}
                      placeholder={t('New aliases')}
                      className={classes.aliasesInput}
                      onChange={this.handleChangeNewAlias.bind(this)}
                      value={this.state.newAlias}
                      onKeyDown={(e) => {
                        if (e.keyCode === 13) {
                          if (
                            enableReferences
                            && !this.state.openCommitCreate
                          ) {
                            return this.handleOpenCommitCreate();
                          }
                          return submitForm();
                        }
                        return true;
                      }}
                    />
                    {enableReferences && (
                      <CommitMessage
                        handleClose={this.handleCloseCommitCreate.bind(this)}
                        open={this.state.openCommitCreate}
                        submitForm={submitForm}
                        disabled={isSubmitting}
                        validateForm={validateForm}
                        setFieldValue={setFieldValue}
                        values={values}
                        id={stixDomainObject.id}
                      />
                    )}
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
        {enableReferences && (
          <Formik
            initialValues={{}}
            onSubmit={this.onSubmitDeleteAlias.bind(this)}
            validationSchema={aliasValidation(t)}
          >
            {({
              submitForm,
              isSubmitting,
              validateForm,
              setFieldValue,
              values,
            }) => (
              <Form style={{ float: 'right' }}>
                <CommitMessage
                  handleClose={this.handleCloseCommitDelete.bind(this)}
                  open={this.state.openCommitDelete}
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  validateForm={validateForm}
                  setFieldValue={setFieldValue}
                  values={values}
                  id={stixDomainObject.id}
                />
              </Form>
            )}
          </Formik>
        )}
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
  enableReferences: PropTypes.bool,
};

export default R.compose(inject18n, withStyles(styles))(StixDomainObjectHeader);
