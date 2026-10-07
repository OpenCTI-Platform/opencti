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
import { CoverageInformation } from '../SecurityCoverage-types';

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
    details?: SecurityCoverageResultFormData,
    entities?: SelectedEntities | null,
    formRelsData?: StixCoreRelationshipCreationFormInput,
  ) => {
    if (!details || submitting) {
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

    const related_entities = entities ? {
      ...(entities ?? {}),
      relationships_config: relationshipInput,
    } : undefined;

    const coverage_information = details.coverageInformation.flatMap((cov) => {
      return cov.coverage_name && cov.coverage_score ? cov : [];
    }) as CoverageInformation[];

    commitCreation({
      variables: {
        input: {
          name: details.name,
          description: details.description,
          createdBy: details.createdBy?.value,
          objectMarking: details.objectMarking.map((v) => v.value),
          objectLabel: details.objectLabel.map((v) => v.value),
          confidence: parseInt(String(details.confidence), 10),
          coverage_information,
          external_uri: details.externalUri,
          coverage_valid_from: details.validFrom,
          coverage_valid_to: details.validTo,
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
            onStepClick={setActiveStep}
          />

          <div style={{ ...stepVisibility(0) }}>
            <SecurityCoverageResultFormDetails
              onCancel={close}
              onSubmit={(val) => submit(val)}
              onNext={(values) => {
                setFormDetails(values);
                setActiveStep((a) => a + 1);
              }}
              initValues={formDetails}
            />
          </div>

          <div style={{ ...stepVisibility(1) }}>
            <SelectEntitiesToCoverStep
              onCancel={close}
              coveredEntity={objectCovered}
              onNext={(entities, elements) => {
                setSelectedEntities(entities);
                setRelToEntities(elements);
                setActiveStep((a) => a + 1);
              }}
              onCreate={(entities) => {
                submit(formDetails, entities);
              }}
            />
          </div>

          {formDetails && (
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
                  submit(formDetails, selectedEntities, relsData);
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
