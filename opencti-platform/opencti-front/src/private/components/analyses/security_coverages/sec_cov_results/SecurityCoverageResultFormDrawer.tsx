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
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { SecurityCoverageResultCreationMutation } from './__generated__/SecurityCoverageResultCreationMutation.graphql';
import { serializeFilterGroupForBackend } from 'src/utils/filters/filtersUtils';

const fragment = graphql`
  fragment SecurityCoverageResultFormDrawerFragment on SecurityCoverage {
    id
    objectCovered {
      id
      parent_types
    }
  }
`;

const securityCoverageResultMutation = graphql`
  mutation SecurityCoverageResultCreationMutation($input: SecurityCoverageResultAddInput!) {
    securityCoverageResultAdd(input: $input) {
      id
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
  const { objectCovered, id } = useFragment(fragment, data);

  const [activeStep, setActiveStep] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [formDetails, setFormDetails] = useState<SecurityCoverageResultFormData>();
  const [selectedEntities, setSelectedEntities] = useState<SelectedEntities | null>();

  const [commitCreation, submitting] = useApiMutation<SecurityCoverageResultCreationMutation>(
    securityCoverageResultMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Security-Coverage-Result')} ${t_i18n('successfully created')}` },
  );

  const close = () => {
    setDrawerOpen(false);
    setActiveStep(0);
    setFormDetails(undefined);
    setSelectedEntities(undefined);
  };

  const onSubmit = () => {
    if (!formDetails) {
      return;
    }

    const values = {
      name: formDetails.name,
      coverage_information: formDetails.coverageInformation,
      coverage_valid_from: formDetails.validFrom,
      coverage_valid_to: formDetails.validTo,
      add_related_entities: selectedEntities ? {
        selected_ids: selectedEntities.selected_ids,
        filters: selectedEntities.filters ? serializeFilterGroupForBackend(selectedEntities.filters) : undefined,
        excluded_ids: selectedEntities.excluded_ids,
        search: selectedEntities.search,
      } : null,
      resultOf: id,
    };

    commitCreation({
      variables: {
        input: values,
      },
      onCompleted: () => {
        close();
      },
    });
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
              initValues={formDetails}
            />
          )}

          {activeStep === 1 && (
            <SelectEntitiesToCoverStep
              coveredEntity={objectCovered}
              onSelectEntities={(entities) => {
                setSelectedEntities(entities);
                setActiveStep((a) => a + 1);
              }}
              onPrevious={() => setActiveStep((a) => a - 1)}
            />
          )}

          {activeStep === 2 && (
            <Button onClick={() => onSubmit()} disabled={submitting}>
              Validate
            </Button>
          )}
        </>
      </Drawer>
    </>
  );
};

export default SecurityCoverageResultFormDrawer;
