import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import Skeleton from '@material-ui/lab/Skeleton';
import RiskPopover from './RiskPopover';
import inject18n from '../../../../components/i18n';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import RiskTrackingLines, {
  RiskTrackingLinesQuery,
} from './RiskTrackingLines';
import { QueryRenderer } from '../../../../relay/environment';
import { toastGenericError } from '../../../../utils/bakedToast';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class RiskTracking extends Component {
  handleOpenNewCreation() {
    this.props.history.push({
      pathname: '/activities/risk_assessment/risks',
      openNewCreation: true,
    });
  }

  render() {
    const {
      t,
      classes,
      risk,
      riskId,
      history,
    } = this.props;
    return (
      <>
        <CyioDomainObjectHeader
          disabled={true}
          name={risk.name}
          history={history}
          cyioDomainObject={risk}
          PopoverComponent={<RiskPopover />}
          goBack='/activities/risk_assessment/risks'
          handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
        // OperationsComponent={<RiskDeletion />}
        // handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
        <QueryRenderer
          query={RiskTrackingLinesQuery}
          variables={{ id: riskId }}
          render={({ props, retry, error }) => {
            if (error) {
              return toastGenericError('Failed to get Tracking Data');
            }
            if (props) {
              return (
                <RiskTrackingLines
                  history={history}
                  riskId={riskId}
                  data={props.risk}
                  refreshQuery={retry}
                />
              );
            }
            return (
              <div style={{ height: '100%' }}>
                <Typography
                  variant="h4"
                  gutterBottom={true}
                  style={{ float: 'left', marginBottom: 15 }}
                >
                  {t('Risk Log')}
                </Typography>
                <div className="clearfix" />
                <Paper classes={{ root: classes.paper }} elevation={2}>
                  <List>
                    {Array.from(Array(5), (e, i) => (
                      <ListItem
                        key={i}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatarDisabled }}>
                            {i}
                          </Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
                              width="90%"
                              height={15}
                              style={{ marginBottom: 10 }}
                            />
                          }
                          secondary={
                            <Skeleton
                              animation="wave"
                              variant="rect"
                              width="90%"
                              height={15}
                            />
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </div>
            );
          }}
        />
      </>
    );
  }
}

RiskTracking.propTypes = {
  risk: PropTypes.string,
  riskId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RiskTracking);
