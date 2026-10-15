import { useState } from 'react';

import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import Drawer from '../../../common/drawer/Drawer';
import SecurityCoverageResultsDropdown from './SecurityCoverageResultsDropdown';
import { useFormatter } from '../../../../../components/i18n';
import SecurityCoverageResultFormSteps from './SecurityCoverageResultFormSteps';
import SecurityCoverageResultFormDetails, { SecurityCoverageResultFormData } from './SecurityCoverageResultFormDetails';
import SelectEntitiesToCoverStep from '../security_coverage_creation/select_entities_to_cover_step/SelectEntitiesToCoverStep';
import { SecurityCoverageResultFormDrawerFragment$key } from './__generated__/SecurityCoverageResultFormDrawerFragment.graphql';
import { SelectedEntities } from '../security_coverage_creation/SecurityCoverageCreation-types';
import { SecurityCoverageResultCreationMutation } from './__generated__/SecurityCoverageResultCreationMutation.graphql';
import { SecurityCoverageResultEditionMutation } from './__generated__/SecurityCoverageResultEditionMutation.graphql';
import StixCoreRelationshipCreationForm from '../../../common/stix_core_relationships/StixCoreRelationshipCreationForm';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { UseEntityToggleType } from '../../../../../utils/hooks/useEntityToggle';
import { StixCoreRelationshipCreationFormInput } from '../../../common/stix_core_relationships/StixCoreRelationshipCreation';
import { formatDate } from '../../../../../utils/Time';
import { CoverageInformation } from '../SecurityCoverage-types';
import { MESSAGING$ } from '../../../../../relay/environment';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import SecurityCoverageResultList from './SecurityCoverageResultList';
import { resultToFormData, SecurityCoverageResultToEdit } from './SecurityCoverageResultForm-utils';

const fragment = graphql`
  fragment SecurityCoverageResultFormDrawerFragment on SecurityCoverage {
    id
    objectCovered {
      id
      parent_types
    }
    results {
      id
      name
      description
      confidence
      external_uri
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
      createdBy {
        id
        name
        entity_type
      }
      objectMarking {
        id
        definition
        definition_type
        x_opencti_color
        x_opencti_order
      }
      objectLabel {
        id
        value
        color
      }
    }
  }
`;

const securityCoverageResultMutation = graphql`
  mutation SecurityCoverageResultCreationMutation($input: SecurityCoverageResultAddInput!) {
    securityCoverageResultAdd(input: $input) {
      id
      # Refresh the list of results of the coverage in the store,
      # so the results table includes the newly created one.
      resultOf {
        ...SecurityCoverageResultFormDrawerFragment
      }
    }
  }
`;

const securityCoverageResultEditionMutation = graphql`
  mutation SecurityCoverageResultEditionMutation($id: ID!, $input: SecurityCoverageResultEditInput!) {
    securityCoverageResultEdit(id: $id, input: $input) {
      id
      # Refresh the results of the coverage in the store,
      # so the update form shows the new values.
      resultOf {
        ...SecurityCoverageResultFormDrawerFragment
      }
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
  const draftContext = useDraftContext();
  const { objectCovered, id, results } = useFragment(fragment, data);

  const [activeStep, setActiveStep] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [isUpdate, setIsUpdate] = useState(false);
  const [resultToEdit, setResultToEdit] = useState<SecurityCoverageResultToEdit>();
  // In update mode, the first step is the selection of the result to update.
  const offset = isUpdate ? 1 : 0;

  // Data of the differents steps.
  const [formDetails, setFormDetails] = useState<SecurityCoverageResultFormData>();
  const [selectedEntities, setSelectedEntities] = useState<SelectedEntities | null>();
  const [relToEntities, setRelToEntities] = useState<UseEntityToggleType[]>();

  const [commitCreation, creating] = useApiMutation<SecurityCoverageResultCreationMutation>(
    securityCoverageResultMutation,
  );
  const [commitEdition, updating] = useApiMutation<SecurityCoverageResultEditionMutation>(
    securityCoverageResultEditionMutation,
  );
  const submitting = creating || updating;

  const notifySuccess = (hasRelatedEntities: boolean) => {
    const entityType = t_i18n('entity_Security-Coverage-Result');
    const successMessage = isUpdate
      ? t_i18n('{entity_type} successfully updated', { values: { entity_type: entityType } })
      : t_i18n('{entity_type} successfully created', { values: { entity_type: entityType } });
    if (!hasRelatedEntities) {
      MESSAGING$.notifySuccess(successMessage);
      return;
    }
    const monitoringLink = !draftContext
      ? <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>
      : t_i18n('the draft processes tab');
    MESSAGING$.notifySuccess(
      <span>
        {successMessage}.{' '}
        {t_i18n('Has-covered relationships are being created by a background task and will appear in the results after a refresh. You can monitor it on {link}.', {
          values: { link: monitoringLink },
        })}
      </span>,
    );
  };

  const open = (update: boolean) => {
    setIsUpdate(update);
    setDrawerOpen(true);
  };

  const close = () => {
    setActiveStep(0);
    setDrawerOpen(false);
    setIsUpdate(false);
    setResultToEdit(undefined);
    setFormDetails(undefined);
    setSelectedEntities(undefined);
    setRelToEntities(undefined);
  };

  // Using CSS instead of JSX conditions to keep state of selected
  // entities in step 2.
  const stepVisibility = (step: number) => {
    return {
      display: activeStep === offset + step ? 'block' : 'none',
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
      // A score of 0 is valid, only drop rows left empty.
      return cov.coverage_name && Number.isFinite(cov.coverage_score) ? cov : [];
    }) as CoverageInformation[];

    const confidence = parseInt(String(details.confidence), 10);
    const input = {
      name: details.name,
      description: details.description,
      // An empty confidence is not sent, instead of NaN.
      confidence: Number.isNaN(confidence) ? undefined : confidence,
      createdBy: details.createdBy?.value,
      objectMarking: details.objectMarking.map((v) => v.value),
      objectLabel: details.objectLabel.map((v) => v.value),
      coverage_information,
      external_uri: details.externalUri,
      coverage_valid_from: details.validFrom,
      coverage_valid_to: details.validTo,
      add_related_entities: related_entities,
    };
    const onCompleted = () => {
      notifySuccess(!!related_entities);
      close();
    };

    if (isUpdate && resultToEdit) {
      commitEdition({
        // Send null to clear the author of the result.
        variables: { id: resultToEdit.id, input: { ...input, createdBy: input.createdBy ?? null } },
        onCompleted,
      });
      return;
    }

    commitCreation({
      variables: {
        input: {
          ...input,
          resultOf: id,
        },
      },
      onCompleted,
    });
  };

  if (!objectCovered) {
    return null;
  }

  return (
    <>
      <SecurityCoverageResultsDropdown
        onCreate={() => open(false)}
        onUpdate={() => open(true)}
        canUpdate={(results ?? []).length > 0}
      />

      <Drawer
        open={drawerOpen}
        onClose={close}
        title={isUpdate ? t_i18n('Update a security coverage result') : t_i18n('Create Security Coverage Result')}
      >
        <>
          <SecurityCoverageResultFormSteps
            activeStep={activeStep}
            onStepClick={setActiveStep}
            isUpdate={isUpdate}
          />

          {isUpdate && activeStep === 0 && (
            <SecurityCoverageResultList
              results={results ?? []}
              onCancel={close}
              onSelect={(result) => {
                setResultToEdit(result);
                setFormDetails(resultToFormData(result));
                setSelectedEntities(undefined);
                setRelToEntities(undefined);
                setActiveStep(1);
              }}
            />
          )}

          <div style={{ ...stepVisibility(0) }}>
            <SecurityCoverageResultFormDetails
              onCancel={close}
              onSubmit={(val) => submit(val)}
              onNext={(values) => {
                setFormDetails(values);
                setActiveStep((a) => a + 1);
              }}
              initValues={formDetails}
              // The result being updated is not a duplicate of itself.
              existingResults={results?.filter((r) => r.id !== resultToEdit?.id)}
              isUpdate={isUpdate}
            />
          </div>

          {(!isUpdate || resultToEdit) && (
            <div style={{ ...stepVisibility(1) }}>
              <SelectEntitiesToCoverStep
                key={resultToEdit?.id}
                onCancel={close}
                coveredEntity={objectCovered}
                excludedCoveredResultId={resultToEdit?.id}
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
          )}

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
