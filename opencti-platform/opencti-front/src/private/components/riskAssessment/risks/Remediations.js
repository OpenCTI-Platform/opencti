import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
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
    riskId,
    history,
  } = props;
  const [openCreation, setOpenCreation] = React.useState(false);

  const handleCreation = () => {
    setOpenCreation(true);
  };
  const handleOpenCreation = () => {
    setOpenCreation(false);
  };

  // const handleOpenNewCreation = () => {
  //   props.history.push({
  //     pathname: '/activities/risk assessment/risks',
  //     openNewCreation: true,
  //   });
  // };
  return (
    <div className={classes.container}>
      {/* {!openCreation ? (
        <>
        </>) : ( */}
          <CyioDomainObjectHeader
            disabled={true}
            history={history}
            name={remediation.name}
            cyioDomainObject={remediation}
            handleOpenCreation={handleOpenCreation}
            goBack='/activities/risk assessment/risks'
            // PopoverComponent={<DevicePopover />}
            // handleOpenNewCreation={handleOpenNewCreation.bind(this)}
            // OperationsComponent={<RiskDeletion />}
          />
          <TopMenuRisk risk={remediation.name}/>
          <Grid item={true} xs={12}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t('Remediations')}
            </Typography>
            {/* <Security
              needs={[KNOWLEDGE_KNUPDATE]}
              placeholder={<div style={{ height: 29 }} />}
            > */}
            <IconButton
              color="default"
              aria-label="Label"
              onClick={handleCreation}
              style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            >
              <Add fontSize="small" />
            </IconButton>
            {/* </Security> */}
            <RemediationEntities
              history={history}
              entityId={remediation.id}
              riskId={riskId.id}
            />
          </Grid>
        <RemediationCreation
          remediationId={remediation.id}
          riskId={riskId.id}
          history={history}
          openCreation={openCreation}
          handleOpenCreation={handleOpenCreation}
        />
      {/* )} */}
      {/* </Grid> */}
    </div>
  );
};

Remediations.propTypes = {
  remediation: PropTypes.object,
  riskId: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Remediations);
