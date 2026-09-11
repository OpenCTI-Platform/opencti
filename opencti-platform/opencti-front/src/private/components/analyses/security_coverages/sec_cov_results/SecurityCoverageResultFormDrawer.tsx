import { useState } from 'react';

import { graphql, useFragment } from 'react-relay';
import Drawer from '../../../common/drawer/Drawer';
import SecurityCoverageResultsDropdown from './SecurityCoverageResultsDropdown';
import { useFormatter } from '../../../../../components/i18n';
import SecurityCoverageResultFormSteps from './SecurityCoverageResultFormSteps';
import SecurityCoverageResultFormDetails, { SecurityCoverageResultFormData } from './SecurityCoverageResultFormDetails';
import SelectEntitiesToCoverStep from '../security_coverage_creation/select_entities_to_cover_step/SelectEntitiesToCoverStep';
import { SecurityCoverageResultFormDrawerFragment$key } from './__generated__/SecurityCoverageResultFormDrawerFragment.graphql';
import { SelectedEntities } from '../security_coverage_creation/SecurityCoverageCreation-types';
import Button from '../../../../../components/common/button/Button';

const fragment = graphql`
  fragment SecurityCoverageResultFormDrawerFragment on SecurityCoverage {
    id
    objectCovered {
      id
      parent_types
    }
  }
`;

interface SecurityCoverageResultFormDrawerProps {
  data: SecurityCoverageResultFormDrawerFragment$key;
}

const SecurityCoverageResultFormDrawer = ({
  data,
}: SecurityCoverageResultFormDrawerProps) => {
  const { t_i18n } = useFormatter();
  const { objectCovered } = useFragment(fragment, data);

  const [activeStep, setActiveStep] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [formDetails, setFormDetails] = useState<SecurityCoverageResultFormData>();
  const [selectedEntities, setSelectedEntities] = useState<SelectedEntities | null>();

  const close = () => setDrawerOpen(false);

  const onSubmit = () => {
    console.log(formDetails, selectedEntities);
  };

  if (!objectCovered) {
    return null;
  }

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

          {activeStep === 1 && (
            <SelectEntitiesToCoverStep
              coveredEntity={objectCovered}
              onSelectEntities={(entities) => {
                setSelectedEntities(entities);
                setActiveStep((a) => a + 1);
              }}
            />
          )}

          {activeStep === 2 && (
            <Button onClick={() => onSubmit()}>
              Validate
            </Button>
          )}
        </>
      </Drawer>
    </>
  );
};

export default SecurityCoverageResultFormDrawer;
