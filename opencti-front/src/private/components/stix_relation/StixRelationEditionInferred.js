import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import MenuItem from '@material-ui/core/MenuItem';
import { Link } from 'react-router-dom';
import { Formik, Field, Form } from 'formik';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import Select from '../../../components/Select';
import TextField from '../../../components/TextField';
import { resolveLink } from '../../../utils/Entity';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '30%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
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
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  button: {
    float: 'right',
    backgroundColor: '#f44336',
    borderColor: '#f44336',
    color: '#ffffff',
    '&:hover': {
      backgroundColor: '#c62828',
      borderColor: '#c62828',
    },
  },
  buttonLeft: {
    float: 'left',
  },
});

class StixRelationEditionInferred extends Component {
  render() {
    const {
      classes, t, stixDomainEntity, open, handleClose, stixRelationId,
    } = this.props;
    const link = stixDomainEntity ? resolveLink(stixDomainEntity.type) : '';
    return (
      <Drawer open={open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={handleClose.bind(this)}>
        <div>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6' classes={{ root: classes.title }}>
              {t('Update a relationship')}
            </Typography>
            <div className='clearfix'/>
          </div>
          <div className={classes.container}>
            <Formik
              enableReinitialize={true}
              initialValues={{
                weight: '', first_seen: '', last_seen: '', description: '',
              }}
              render={() => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='weight'
                         disabled={true}
                         component={Select}
                         label={t('Confidence level')}
                         inputProps={{
                           name: 'weight',
                           id: 'weight',
                         }}
                         containerstyle={{ marginTop: 10, width: '100%' }}
                  >
                    <MenuItem value='1'>{t('Very low')}</MenuItem>
                    <MenuItem value='2'>{t('Low')}</MenuItem>
                    <MenuItem value='3'>{t('Medium')}</MenuItem>
                    <MenuItem value='4'>{t('High')}</MenuItem>
                    <MenuItem value='5'>{t('Very high')}</MenuItem>
                  </Field>
                  <Field name='first_seen' component={TextField} label={t('First seen')}
                         fullWidth={true} style={{ marginTop: 10 }} disabled={true}/>
                  <Field name='last_seen' component={TextField} label={t('Last seen')}
                         fullWidth={true} style={{ marginTop: 10 }} disabled={true}/>
                  <Field name='description' component={TextField} label={t('Description')}
                         fullWidth={true} multiline={true} rows={4} style={{ marginTop: 10 }} disabled={true}/>
                </Form>
              )}
            />
            {stixDomainEntity
              ? <Button variant='contained' color='primary' component={Link} to={`${link}/${stixDomainEntity.id}/knowledge/relations/${stixRelationId}`} classes={{ root: classes.buttonLeft }}>
                {t('Details')}
              </Button> : ''}
          </div>
        </div>
      </Drawer>
    );
  }
}

StixRelationEditionInferred.propTypes = {
  stixRelationId: PropTypes.string,
  stixDomainEntity: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationEditionInferred);
