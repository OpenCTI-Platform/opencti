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
import { SecurityCoverageResultCreationMutation } from './__generated__/SecurityCoverageResultCreationMutation.graphql';
import StixCoreRelationshipCreationForm from '../../../common/stix_core_relationships/StixCoreRelationshipCreationForm';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { UseEntityToggleType } from '../../../../../utils/hooks/useEntityToggle';
import { StixCoreRelationshipCreationFormInput } from '../../../common/stix_core_relationships/StixCoreRelationshipCreation';
import { formatDate } from '../../../../../utils/Time';

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

  // Data of the differents steps.
  const [formDetails, setFormDetails] = useState<SecurityCoverageResultFormData>();
  const [selectedEntities, setSelectedEntities] = useState<SelectedEntities | null>();
  const [relToEntities, setRelToEntities] = useState<UseEntityToggleType[]>();

  const [commitCreation, submitting] = useApiMutation<SecurityCoverageResultCreationMutation>(
    securityCoverageResultMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Security-Coverage-Result')} ${t_i18n('successfully created')}` },
  );

  const close = () => {
    setActiveStep(0);
    setDrawerOpen(false);
    setFormDetails(undefined);
    setSelectedEntities(undefined);
    setRelToEntities(undefined);
  };

  // Using CSS instead of JSX conditions to keep state of selected
  // entities in step 2.
  const stepVisibility = (step: number) => {
    return {
      display: activeStep === step ? 'block' : 'none',
    };
  };

  const submit = (
    entities?: SelectedEntities,
    formRelsData?: StixCoreRelationshipCreationFormInput,
  ) => {
    if (!formDetails || submitting) {
      return;
    }

    const relationshipInput = formRelsData ? {
      ...formRelsData,
      confidence: parseInt(formRelsData.confidence, 10),
      fromId: id,
      toId: id,
      start_time: formatDate(formRelsData.start_time),
      stop_time: formatDate(formRelsData.stop_time),
      killChainPhases: formRelsData.killChainPhases.map((k) => k.value),
      createdBy: formRelsData.createdBy?.value,
      objectMarking: formRelsData.objectMarking.map((k) => k.value),
      externalReferences: formRelsData.externalReferences.map((k) => k.value),
    } : undefined;

    const related_entities = entities || relationshipInput ? {
      ...(entities ?? {}),
      relationships_config: relationshipInput,
    } : undefined;

    commitCreation({
      variables: {
        input: {
          name: formDetails.name,
          description: formDetails.description,
          createdBy: formDetails.createdBy?.value,
          objectMarking: formDetails.objectMarking.map((v) => v.value),
          objectLabel: formDetails.objectLabel.map((v) => v.value),
          confidence: parseInt(String(formDetails.confidence), 10),
          coverage_information: formDetails.coverageInformation,
          external_uri: formDetails.externalUri,
          coverage_valid_from: formDetails.validFrom,
          coverage_valid_to: formDetails.validTo,
          add_related_entities: related_entities,
          resultOf: id,
        },
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
          <SecurityCoverageResultFormSteps
            activeStep={activeStep}
            displayRelStep={!!selectedEntities}
            onStepClick={setActiveStep}
          />

          <div style={{ ...stepVisibility(0) }}>
            <SecurityCoverageResultFormDetails
              onCancel={close}
              onSubmit={(values) => {
                setFormDetails(values);
                setActiveStep((a) => a + 1);
              }}
              initValues={formDetails}
            />
          </div>

          <div style={{ ...stepVisibility(1) }}>
            <SelectEntitiesToCoverStep
              endIfNoSelection
              onCancel={close}
              coveredEntity={objectCovered}
              onSelectEntities={(entities, elements) => {
                setSelectedEntities(entities);
                setRelToEntities(elements);
                if (!entities) {
                  submit();
                } else {
                  setActiveStep((a) => a + 1);
                }
              }}
            />
          </div>

          {formDetails && !!selectedEntities && (
            <div style={{ ...stepVisibility(2) }}>
              <StixCoreRelationshipCreationForm
                fromEntities={[{
                  entity_type: 'Security-Coverage-Result',
                  name: formDetails.name,
                }]}
                isCoverage
                toEntities={relToEntities}
                toEntityType="Stix-Core-Object"
                relationshipTypes={['has-covered']}
                defaultConfidence={formDetails.confidence}
                defaultCreatedBy={formDetails.createdBy}
                defaultMarkingDefinitions={formDetails.objectMarking}
                onSubmit={(relsData: StixCoreRelationshipCreationFormInput) => {
                  submit(selectedEntities, relsData);
                }}
                handleClose={close}
                handleReverseRelation={undefined}
                handleResetSelection={undefined}
                defaultStartTime={undefined}
                defaultStopTime={undefined}
              />
            </div>
          )}
        </>
      </Drawer>
    </>
  );
};

export default SecurityCoverageResultFormDrawer;
