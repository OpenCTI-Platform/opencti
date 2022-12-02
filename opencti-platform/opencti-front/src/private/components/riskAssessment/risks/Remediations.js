import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import RemediationEntities from './remediations/RemediationEntities';
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
    remediation,
    classes,
    riskId,
    history,
    location,
  } = props;
  const [openCreation, setOpenCreation] = React.useState(false);

  const handleOpenCreation = () => {
    setOpenCreation(false);
  };

  // const handleOpenNewCreation = () => {
  //   props.history.push({
  //     pathname: '/activities/risk_assessment/risks',
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
        goBack='/activities/risk_assessment/risks'
      // PopoverComponent={<DevicePopover />}
      // handleOpenNewCreation={handleOpenNewCreation.bind(this)}
      // OperationsComponent={<RiskDeletion />}
      />
      <RemediationEntities
        history={history}
        location={location}
        entityId={remediation.id}
        riskId={riskId.id}
        openCreation={openCreation}
      />
    </div>
  );
};

Remediations.propTypes = {
  remediation: PropTypes.object,
  riskId: PropTypes.object,
  location: PropTypes.object,
  history: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Remediations);
