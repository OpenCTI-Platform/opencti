import { useState } from 'react';

import Drawer from '../../../common/drawer/Drawer';
import SecurityCoverageResultsDropdown from './SecurityCoverageResultsDropdown';
import { useFormatter } from '../../../../../components/i18n';
import SecurityCoverageResultFormSteps from './SecurityCoverageResultFormSteps';
import SecurityCoverageResultFormDetails, { SecurityCoverageResultFormData } from './SecurityCoverageResultFormDetails';

const SecurityCoverageResultFormDrawer = () => {
  const { t_i18n } = useFormatter();
  const [activeStep, setActiveStep] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [formDetails, setFormDetails] = useState<SecurityCoverageResultFormData>();

  const close = () => setDrawerOpen(false);

  return (
    <>
      <SecurityCoverageResultsDropdown
        onCreate={() => setDrawerOpen(true)}
      />

      <Drawer
        open={drawerOpen}
        onClose={close}
        title={t_i18n('Create Security Coverage Result')}
      >
        <>
          <SecurityCoverageResultFormSteps activeStep={activeStep} />

          {activeStep === 0 && (
            <SecurityCoverageResultFormDetails
              onCancel={close}
              onSubmit={(values) => {
                setFormDetails(values);
                setActiveStep((a) => a + 1);
              }}
            />
          )}
        </>
      </Drawer>
    </>
  );
};

export default SecurityCoverageResultFormDrawer;
