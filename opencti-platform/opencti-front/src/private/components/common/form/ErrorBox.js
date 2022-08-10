/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import Typography from '@material-ui/core/Typography';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import {
  Dialog,
  DialogContent,
  DialogActions,
  DialogTitle,
} from '@material-ui/core';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  inputTextField: {
    color: 'white',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  textField: {
    background: theme.palette.header.background,
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
});

class ErrorBox extends Component {
  handleErrorResponse(errorMessage) {
    let FieldName;
    function title(str) {
      return str.replace(/(^|\s)\S/g, (s) => s.toUpperCase());
    }
    if ((/(enum)\b/).test(errorMessage)) {
      FieldName = errorMessage.match(/(input)\.\w+/);
      const FilteredValue = FieldName[0].replace(/(input.)/, '').replace('_', ' ');
      return `Value of ${title(FilteredValue)} in invalid`;
    }
    if ((/; ?(Field)/).test(errorMessage)) {
      FieldName = errorMessage.match(/; ?(Field).+/)[0].replace(/; ?/, '');
      return FieldName;
    }
    FieldName = errorMessage.match(/\bValue\b.+/);
    return FieldName[0];
  }

  render() {
    const {
      t, classes, history, pathname, error,
    } = this.props;
    return (
      <>
        <Dialog
          open={Object.keys(error).length}
          fullWidth={true}
          maxWidth='md'
        >
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t('ERROR')}
          </DialogTitle>
          <DialogContent>
            <Typography style={{ marginBottom: '20px' }}>
              Sorry. Something went wrong and DarkLight Support has been notified. Please try again or contact <strong style={{ color: '#075AD3' }}>Support@darklight.ai</strong> for assistance.
            </Typography>
            {Object.keys(error).length && error.map((value, key) => {
              if (value.extensions.code.includes('BAD_USER_INPUT')) {
                return (
                  <>
                    <Accordion
                      disableGutters
                      square
                      key={key}
                    >
                      <AccordionSummary>
                        <Typography variant='h2'>
                          {t(value.extensions.code)}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {this.handleErrorResponse(value.message)}
                      </AccordionDetails>
                    </Accordion>
                  </>
                );
              }
              return <></>;
            })}
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => history.push(pathname)}
            >
              {t('Cancel')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

ErrorBox.propTypes = {
  pathname: PropTypes.string,
  history: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  error: PropTypes.object,
  fldt: PropTypes.func,
};

export default compose(withRouter, inject18n, withStyles(styles))(ErrorBox);
