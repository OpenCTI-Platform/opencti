import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import IconButton from '@material-ui/core/IconButton';
import {
  Add,
} from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import { withStyles } from '@material-ui/core';
import inject18n from '../../../../../components/i18n';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import RemediationEntities from './RemediationEntities';
import { QueryRenderer } from '../../../../../relay/environment';
import RiskDeletion from '../RiskDeletion';
import AddRemediation from './AddRemediation';
import RemediationCreation from './RemediationCreation';
// import StixCyberObservableLinks, {
//   riskLinksQuery,
// } from './StixCyberObservableLinks';
// import StixCyberObservableIndicators from './StixCyberObservableIndicators';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const Remediation = (props) => {
  const { t, risk, classes } = props;
  const [openCreation, setOpenCreation] = React.useState(false);
  const paginationOptions = {
    elementId: risk.id,
    orderBy: 'created_at',
    orderMode: 'desc',
  };

  const handleCreation = () => {
    setOpenCreation(true);
    // this.props.handleCreation();
  };

  const handleOpenNewCreation = () => {
    this.props.history.push({
      pathname: '/dashboard/risk-assessment/risks',
      openNewCreation: true,
    });
  };
  return (
    <div className={classes.container}>
      {console.log('remediationData', risk)}
      {!openCreation ? (
        <>
          <CyioDomainObjectHeader
            cyioDomainObject={risk}
            // history={history}
            // PopoverComponent={<DevicePopover />}
            // handleDisplayEdit={handleDisplayEdit.bind(this)}
            handleOpenNewCreation={handleOpenNewCreation.bind(this)}
            OperationsComponent={<RiskDeletion />}
          />
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t('Remediation')}
            </Typography>
            {/* <Security
              needs={[KNOWLEDGE_KNUPDATE]}
              placeholder={<div style={{ height: 29 }} />}
            > */}
            <IconButton
              color="secondary"
              aria-label="Label"
              onClick={handleCreation}
              style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            >
              <Add fontSize="small" />
            </IconButton>
            {/* </Security> */}
            <RemediationEntities
              entityId={risk.id}
            />
          </Grid>
        </>) : (
        <RemediationCreation />
      )}
      {/* </Grid> */}
    </div>
  );
};

// const RemediationFragment = createFragmentContainer(
//   Remediation,
//   {
//     risk: graphql`
//       fragment risk on StixCyberObservable {
//         id
//         entity_type
//         ...risk
//         ...risk
//       }
//     `,
//   },
// );

Remediation.propTypes = {
  risk: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Remediation);
