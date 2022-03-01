import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import ExternalReferenceEditionOverview from './ExternalReferenceEditionOverview';

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

class ExternalReferenceEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const { t, classes, handleClose, externalReference } = this.props;
    const { editContext } = externalReference;
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
            {t('Update an external reference')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <ExternalReferenceEditionOverview
            externalReference={this.props.externalReference}
            context={editContext}
          />
        </div>
      </div>
    );
  }
}

ExternalReferenceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  externalReference: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const ExternalReferenceEditionFragment = createFragmentContainer(
  ExternalReferenceEditionContainer,
  {
    externalReference: graphql`
      fragment ExternalReferenceEditionContainer_externalReference on ExternalReference {
        id
        ...ExternalReferenceEditionOverview_externalReference
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ExternalReferenceEditionFragment);
