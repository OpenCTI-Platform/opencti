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
import inject18n from '../../../../components/i18n';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import RemediationEntities from './remediations/RemediationEntities';
import { QueryRenderer } from '../../../../relay/environment';
import RiskDeletion from './RiskDeletion';
import AddRemediation from './remediations/AddRemediation';
import RemediationCreation from './remediations/RemediationCreation';
import TopMenuRisk from '../../nav/TopMenuRisk';
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

const Remediations = (props) => {
  const {
    t,
    remediation,
    classes,
    history,
  } = props;
  const [openCreation, setOpenCreation] = React.useState(false);
  const paginationOptions = {
    elementId: remediation.id,
    orderBy: 'created_at',
    orderMode: 'desc',
  };

  const handleCreation = () => {
    setOpenCreation(true);
    // this.props.handleCreation();
  };

  const handleOpenNewCreation = () => {
    props.history.push({
      pathname: '/dashboard/risk-assessment/risks',
      openNewCreation: true,
    });
  };
  return (
    <div className={classes.container}>
      {console.log('remediationData', remediation)}
      {!openCreation ? (
        <>
          <CyioDomainObjectHeader
            cyioDomainObject={remediation}
            history={history}
            disabled={true}
            // PopoverComponent={<DevicePopover />}
            // handleDisplayEdit={handleDisplayEdit.bind(this)}
            handleOpenNewCreation={handleOpenNewCreation.bind(this)}
            // OperationsComponent={<RiskDeletion />}
          />
          <TopMenuRisk risk={remediation}/>
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t('Remediations')}
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
              entityId={remediation.id}
            />
          </Grid>
        </>) : (
        <RemediationCreation remediationId={remediation.id} history={history}/>
      )}
      {/* </Grid> */}
    </div>
  );
};

// const RemediationFragment = createFragmentContainer(
//   Remediations,
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

Remediations.propTypes = {
  remediation: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Remediations);
