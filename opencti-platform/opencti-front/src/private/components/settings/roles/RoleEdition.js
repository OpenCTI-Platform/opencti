import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import RoleEditionOverview from './RoleEditionOverview';

const styles = (theme) => ({
  header: {
    padding: '20px 20px 20px 60px',
    backgroundColor: theme.palette.background.paper,
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
});

class RoleEdition extends Component {
  render() {
    const { t, classes, handleClose, role } = this.props;
    const { editContext } = role;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a role')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <RoleEditionOverview role={this.props.role} context={editContext} />
        </div>
      </div>
    );
  }
}

RoleEdition.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  role: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RoleEditionFragment = createFragmentContainer(RoleEdition, {
  role: graphql`
    fragment RoleEdition_role on Role {
      id
      ...RoleEditionOverview_role
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RoleEditionFragment);
