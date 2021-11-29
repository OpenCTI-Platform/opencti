import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Switch, Tooltip } from '@material-ui/core';
import Chip from '@material-ui/core/Chip';
import Button from '@material-ui/core/Button';
import Link from '@material-ui/core/Link';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import Launch from '@material-ui/icons/Launch';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, Information } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
});

class RiskDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      risk,
      fd,
      history,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t('Name')}
                </Typography>
                <div style={{ float: 'left', margin: '2px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Name',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.name && t(risk.name)}
              </div>
              <div>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left', marginTop: 20 }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                        <Tooltip
                          title={t(
                            'Description',
                          )}
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <div className={classes.scrollBg}>
                          <div className={classes.scrollDiv}>
                            <div className={classes.scrollObj}>
                            {risk.description && t(risk.description)}
                            </div>
                          </div>
                      </div>
                </div>
                  <div style={{ marginTop: '15px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 5 }}
                  >
                    {t('Risk Status')}
                  </Typography>
                  <div style={{ float: 'left', margin: '6px 0 0 5px' }}>
                    <Tooltip
                      title={t(
                        'Risk Status',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                  >
                    {risk.risk_status && t(risk.risk_status)}
                  </Button>
                </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Impacted Component')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Impacted Component',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        {t('Description')}
                      </div>
                    </div>
                </div>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Detection Source')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Detection Source',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('Lorem Ipsum Dolor Sit Amet')}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('False Positive')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'False Positive',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
              <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                  >
                    {risk.false_positive && t(risk.false_positive)}
                  </Button>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 21 }}
                >
                  {t('Risk Adjusted')}
                </Typography>
                <div style={{ float: 'left', margin: '22px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Risk Adjusted',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                  <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                  >
                    {risk.risk_adjusted && t(risk.risk_adjusted)}
                  </Button>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              <div style={{ marginTop: '37px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Statement')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Statement',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className='scroll-bg'>
                  <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        {risk.statement && t(risk.statement)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div style={{ marginBottom: '12px', marginTop: '6px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 15 }}
                >
                  {t('Deadline')}
                </Typography>
                <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Deadline',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {risk.deadline && fd(risk.deadline)}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Inpacted Assets')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Impacted Assets',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div className={classes.scrollBg}>
                    <div className={classes.scrollDiv}>
                      <div className={classes.scrollObj}>
                        {t('Description')}
                      </div>
                    </div>
                </div>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Impacted Control')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Impacted Control',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {t('Lorem Ipsum Dono Ist')}
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Operationally Required')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Operationally Required',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                  >
                    {t('Approved')}
                  </Button>
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Vendor Dependency')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip
                    title={t(
                      'Vendor Dependency',
                    )}
                  >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                  <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                  >
                    {risk.vendor_dependency && t(risk.vendor_dependency)}
                  </Button>
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

RiskDetailsComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const RiskDetails = createFragmentContainer(
  RiskDetailsComponent,
  {
    risk: graphql`
      fragment RiskDetails_risk on Risk {
        id
        name
        description
        statement
        risk_status
        deadline
        false_positive
        vendor_dependency
        risk_adjusted
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskDetails);
