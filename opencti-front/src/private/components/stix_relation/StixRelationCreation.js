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
import { ArrowRightAlt } from '@material-ui/icons';
import { environment, commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';
import ItemIcon from '../../../components/ItemIcon';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';

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
    position: 'relative',
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
  popover: {
    position: 'absolute',
    color: '#ffffff',
    top: 8,
    right: 5,
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
});

const stixRelationCreationQuery = graphql`
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

const stixRelationValidation = t => Yup.object().shape({
  relationship_typ: Yup.number()
    .required(t('This field is required')),
  weight: Yup.number()
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  description: Yup.string(),
});

class StixRelationCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { step: 1, existingRelations: [] };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    console.log(values);
    commitMutation({
      mutation: stixRelationCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.props.handleResult(response);
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
        this.setState({ existingRelations: data.stixRelations.edges });
      });
    }
  }

  renderForm() {
    const {
      t, classes, handleClose, from, to,
    } = this.props;
    return (
      <Formik
        enableReinitialize={true}
        initialValues={{
          relationship_type: '', weight: '', first_seen: '', last_seen: '', description: '',
        }}
        validationSchema={stixRelationValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={handleClose.bind(this)}
        render={({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <DialogTitle>
              {t('Create a relationship')}
            </DialogTitle>
            <DialogContent>
              <div className={classes.item} style={{
                backgroundColor: itemColor(from.type, true),
                float: 'left',
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
              <div style={{ float: 'left', padding: '26px 0 0 80px', color: '#ffffff' }}>
                <ArrowRightAlt fontSize='large'/>
              </div>
              <div className={classes.item} style={{
                backgroundColor: itemColor(to.type, true),
                float: 'right',
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
                <MenuItem value='gathering'>{t('Gathers')}</MenuItem>
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

  render() {
    const { open, handleClose } = this.props;
    const { existingRelations, step } = this.state;
    return (
      <Dialog open={open} onClose={handleClose.bind(this)}>
        {existingRelations.length === 0 || step === 2 ? this.renderForm() : this.renderForm()}
      </Dialog>
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
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationCreation);
