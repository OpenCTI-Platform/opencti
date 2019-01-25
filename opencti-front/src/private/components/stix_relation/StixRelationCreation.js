import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Field, Form } from 'formik';
import { fetchQuery } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import CircularProgress from '@material-ui/core/CircularProgress';
import { ArrowRightAlt } from '@material-ui/icons';
import { environment, commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';
import { resolveRoles } from '../../../utils/Relation';
import { parse } from '../../../utils/Time';
import ItemIcon from '../../../components/ItemIcon';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';

const styles = theme => ({
  loader: {
    width: '100%',
    height: 180,
    paddingTop: 50,
    textAlign: 'center',
  },
  loaderCircle: {
    display: 'inline-block',
  },
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
  dialogActions: {
    padding: '0 17px 20px 0',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
    borderBottom: '1px solid #ffffff',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
    marginBottom: 10,
  },
  relationCreation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: '#ffffff',
  },
});

export const stixRelationCreationQuery = graphql`
    query StixRelationCreationQuery($fromId: String!, $toId: String!) {
        stixRelations(fromId: $fromId, toId: $toId) {
            edges {
                node {
                    id
                    relationship_type
                    weight
                    description
                    first_seen
                    last_seen
                }
            }
        }
    }
`;

const stixRelationCreationMutation = graphql`
    mutation StixRelationCreationMutation($input: StixRelationAddInput!) {
        stixRelationAdd(input: $input) {
            id
            relationship_type
            weight
            first_seen
            last_seen
        }
    }
`;

export const stixRelationCreationDeleteMutation = graphql`
    mutation StixRelationCreationDeleteMutation($id: ID!) {
        stixRelationEdit(id: $id) {
            delete
        }
    }
`;

const stixRelationValidation = t => Yup.object().shape({
  relationship_type: Yup.string()
    .required(t('This field is required')),
  weight: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  description: Yup.string(),
});

class StixRelationCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { step: 0, existingRelations: [] };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const roles = resolveRoles(values.relationship_type);
    values.fromId = this.props.from.id;
    values.fromRole = roles.fromRole;
    values.toId = this.props.to.id;
    values.toRole = roles.toRole;
    values.first_seen = parse(values.first_seen).format();
    values.last_seen = parse(values.last_seen).format();

    commitMutation({
      mutation: stixRelationCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.setState({ existingRelations: [], step: 0 });
        this.props.handleResult(response.stixRelationAdd);
      },
    });
  }

  componentDidUpdate(prevProps) {
    if ((this.props.from !== prevProps.from && this.props.to !== prevProps.to)
      && (this.props.from !== null && this.props.to !== null)) {
      fetchQuery(environment, stixRelationCreationQuery, {
        fromId: this.props.from.id,
        toId: this.props.to.id,
      }).then((data) => {
        this.setState({
          step: data.stixRelations.edges.length > 0 ? 1 : 2,
          existingRelations: data.stixRelations.edges,
        });
      });
    }
  }

  handleSelectRelation(relation) {
    this.setState({ existingRelations: [], step: 0 });
    this.props.handleResult(relation);
  }

  handleChangeStep() {
    this.setState({ step: 2 });
  }

  handleClose() {
    this.setState({ existingRelations: [], step: 0 });
    this.props.handleClose();
  }

  renderForm() {
    const {
      t, classes, from, to,
    } = this.props;
    return (
      <Formik
        enableReinitialize={true}
        initialValues={{
          relationship_type: '', weight: '', first_seen: '', last_seen: '', description: '',
        }}
        validationSchema={stixRelationValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={this.handleClose.bind(this)}
        render={({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <DialogTitle>
              {t('Create a relationship')}
            </DialogTitle>
            <DialogContent>
              <div className={classes.relationCreate}>
                <div className={classes.item} style={{
                  backgroundColor: itemColor(from.type, true),
                  top: 10,
                  left: 10,
                }}>
                  <div className={classes.itemHeader}>
                    <div className={classes.icon}>
                      <ItemIcon type={from.type} color={itemColor(from.type, false)} size='small'/>
                    </div>
                    <div className={classes.type}>
                      {t(`entity_${from.type}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>{from.name}</span>
                  </div>
                </div>
                <div className={classes.middle} style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize='large'/>
                </div>
                <div className={classes.item} style={{
                  backgroundColor: itemColor(to.type, true),
                  top: 10,
                  right: 10,
                }}>
                  <div className={classes.itemHeader}>
                    <div className={classes.icon}>
                      <ItemIcon type={to.type} color={itemColor(to.type, false)} size='small'/>
                    </div>
                    <div className={classes.type}>
                      {t(`entity_${to.type}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>{to.name}</span>
                  </div>
                </div>
              </div>
              <Field name='relationship_type'
                     component={Select}
                     label={t('Relationship type')}
                     fullWidth={true}
                     displayEmpty={true}
                     inputProps={{
                       name: 'relationship_type',
                       id: 'relationship_type',
                     }}
                     containerstyle={{ marginTop: 20, width: '100%' }}
              >
                <MenuItem value='targets'>{t('Targets')}</MenuItem>
                <MenuItem value='uses'>{t('Uses')}</MenuItem>
                <MenuItem value='attributed-to'>{t('Attributed to')}</MenuItem>
                <MenuItem value='variant-of'>{t('Variant of')}</MenuItem>
                <MenuItem value='gathering'>{t('Part of')}</MenuItem>
                <MenuItem value='related-to'>{t('Related to')}</MenuItem>
                <MenuItem value='localization'>{t('Localized in')}</MenuItem>
              </Field>
              <Field name='weight'
                     component={Select}
                     label={t('Confidence level')}
                     fullWidth={true}
                     displayEmpty={true}
                     inputProps={{
                       name: 'weight',
                       id: 'weight',
                     }}
                     containerstyle={{ marginTop: 20, width: '100%' }}
              >
                <MenuItem value={1}>{t('Very low')}</MenuItem>
                <MenuItem value={2}>{t('Low')}</MenuItem>
                <MenuItem value={3}>{t('Medium')}</MenuItem>
                <MenuItem value={4}>{t('High')}</MenuItem>
                <MenuItem value={5}>{t('Very high')}</MenuItem>
              </Field>
              <Field name='first_seen' component={TextField} label={t('First seen')} fullWidth={true} style={{ marginTop: 20 }}/>
              <Field name='last_seen' component={TextField} label={t('Last seen')} fullWidth={true} style={{ marginTop: 20 }}/>
              <Field name='description' component={TextField} label={t('Description')} fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }}/>
            </DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button variant='contained' onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                {t('Cancel')}
              </Button>
              <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                {t('Create')}
              </Button>
            </DialogActions>
          </Form>
        )}
      />
    );
  }

  renderSelectRelation() {
    const {
      nsd, t, classes, from, to,
    } = this.props;
    const { existingRelations } = this.state;
    return (
      <div>
        <DialogTitle>
          {t('Select a relationship')}
        </DialogTitle>
        <DialogContent>
          {existingRelations.map(relation => (
            <div
              key={relation.node.id}
              className={classes.relation}
              onClick={this.handleSelectRelation.bind(this, relation.node)}
            >
              <div className={classes.item} style={{
                backgroundColor: itemColor(from.type, true),
                top: 10,
                left: 10,
              }}>
                <div className={classes.itemHeader}>
                  <div className={classes.icon}>
                    <ItemIcon type={from.type} color={itemColor(from.type, false)} size='small'/>
                  </div>
                  <div className={classes.type}>
                    {t(`entity_${from.type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>{from.name}</span>
                </div>
              </div>
              <div className={classes.middle}>
                <ArrowRightAlt fontSize='small'/><br/>
                <div style={{
                  padding: '5px 8px 5px 8px',
                  backgroundColor: '#14262c',
                  color: '#ffffff',
                  fontSize: 12,
                  display: 'inline-block',
                }}>{t(`relation_${relation.node.relationship_type}`)}<br/>
                  {t('First obs.')} {nsd(relation.node.first_seen)}<br/>
                  {t('Last obs.')} {nsd(relation.node.last_seen)}
                </div>
              </div>
              <div className={classes.item} style={{
                backgroundColor: itemColor(to.type, true),
                top: 10,
                right: 10,
              }}>
                <div className={classes.itemHeader}>
                  <div className={classes.icon}>
                    <ItemIcon type={to.type} color={itemColor(to.type, false)} size='small'/>
                  </div>
                  <div className={classes.type}>
                    {t(`entity_${to.type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>{to.name}</span>
                </div>
              </div>
              <div className='clearfix'/>
            </div>
          ))}
          <div className={classes.relationCreation} onClick={this.handleChangeStep.bind(this)}>
            <div className={classes.item} style={{
              backgroundColor: '#607d8b',
              top: 10,
              left: 10,
            }}>
              <div className={classes.itemHeader}>
                <div className={classes.icon}>
                  <ItemIcon type={from.type} color='#263238' size='small'/>
                </div>
                <div className={classes.type}>
                  {t(`entity_${from.type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>{from.name}</span>
              </div>
            </div>
            <div className={classes.middle} style={{ paddingTop: 15 }}>
              <ArrowRightAlt fontSize='small'/><br />
              <div style={{
                padding: '5px 8px 5px 8px',
                backgroundColor: '#607d8b',
                color: '#ffffff',
                fontSize: 12,
                display: 'inline-block',
              }}>{t('Create a relationship')}</div>
            </div>
            <div className={classes.item} style={{
              backgroundColor: '#607d8b',
              top: 10,
              right: 10,
            }}>
              <div className={classes.itemHeader}>
                <div className={classes.icon}>
                  <ItemIcon type={to.type} color='#263238' size='small'/>
                </div>
                <div className={classes.type}>
                  {t(`entity_${to.type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>{to.name}</span>
              </div>
            </div>
            <div className='clearfix'/>
          </div>
        </DialogContent>
      </div>
    );
  }

  renderLoader() {
    return (
        <div className={this.props.classes.loader}>
          <CircularProgress size={80} thickness={2} className={this.props.classes.loaderCircle}/>
        </div>
    );
  }

  render() {
    const { open } = this.props;
    const { step } = this.state;
    if (this.props.from !== null && this.props.to !== null) {
      return (
        <Dialog
          open={open}
          onClose={this.handleClose.bind(this)}
          maxWidth='md'
          fullWidth={true}
        >
          {step === 0 ? this.renderLoader() : '' }
          {step === 1 ? this.renderSelectRelation() : ''}
          {step === 2 ? this.renderForm() : ''}
        </Dialog>
      );
    }
    return (
      <div style={{ display: 'none' }}> &nbsp; </div>
    );
  }
}

StixRelationCreation.propTypes = {
  open: PropTypes.bool,
  from: PropTypes.object,
  to: PropTypes.object,
  handleResult: PropTypes.func,
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationCreation);
