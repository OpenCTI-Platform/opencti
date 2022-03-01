import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import RegionEditionOverview from './RegionEditionOverview';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
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
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class RegionEditionContainer extends Component {
  render() {
    const { t, classes, handleClose, region } = this.props;
    const { editContext } = region;
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
            {t('Update a region')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <RegionEditionOverview
            region={this.props.region}
            enableReferences={this.props.enableReferences}
            context={editContext}
            handleClose={handleClose.bind(this)}
          />
        </div>
      </div>
    );
  }
}

RegionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  region: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RegionEditionFragment = createFragmentContainer(RegionEditionContainer, {
  region: graphql`
    fragment RegionEditionContainer_region on Region {
      id
      ...RegionEditionOverview_region
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
)(RegionEditionFragment);
