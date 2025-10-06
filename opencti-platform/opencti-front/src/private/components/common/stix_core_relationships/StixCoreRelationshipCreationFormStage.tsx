import React, { FunctionComponent, useContext, useMemo } from 'react';
import { graphql, useFragment } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityToMutation,
  TargetEntity,
} from './StixCoreRelationshipCreationFromEntity';
import { handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { CreateRelationshipContext } from './CreateRelationshipContextProvider';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { StixCoreRelationshipCreationFormStage_stixCoreObject$key } from './__generated__/StixCoreRelationshipCreationFormStage_stixCoreObject.graphql';

interface StixCoreRelationshipCreationFormStageProps {
  targetEntities: TargetEntity[];
  data: StixCoreRelationshipCreationFormStage_stixCoreObject$key;
  handleResetSelection: () => void;
  handleClose: () => void;
}

const fragment = graphql`
  fragment StixCoreRelationshipCreationFormStage_stixCoreObject on StixCoreObject {
    id
    representative {
      main
    }
    entity_type
  }
`;

const StixCoreRelationshipCreationFormStage: FunctionComponent<StixCoreRelationshipCreationFormStageProps> = ({
  targetEntities,
  data,
  handleResetSelection,
  handleClose,
}) => {
  const stixCoreObject = useFragment(fragment, data);

  const { state: {
    relationshipTypes: allowedRelationshipTypes,
    reversed,
    handleReverseRelation,
    paginationOptions,
    connectionKey,
    onCreate,
  } } = useContext(CreateRelationshipContext);

  const [commitRelationshipCreationMutation] = useApiMutation(reversed
    ? stixCoreRelationshipCreationFromEntityToMutation
    : stixCoreRelationshipCreationFromEntityFromMutation);

  const sourceEntity: TargetEntity = stixCoreObject;

  const fromEntities = useMemo(
    () => (reversed ? targetEntities : [sourceEntity]),
    [reversed, targetEntities, sourceEntity],
  );
  const toEntities = useMemo(
    () => (reversed ? [sourceEntity] : targetEntities),
    [reversed, targetEntities, sourceEntity],
  );

  const onSubmit: FormikConfig<StixCoreRelationshipCreationFromEntityForm>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = reversed ? targetEntity.id : sourceEntity.id;
      const toEntityId = reversed ? sourceEntity.id : targetEntity.id;
      const finalValues = {
        ...values,
        confidence: parseInt(values.confidence, 10),
        fromId: fromEntityId,
        toId: toEntityId,
        start_time: formatDate(values.start_time),
        stop_time: formatDate(values.stop_time),
        killChainPhases: values.killChainPhases.map((kcp) => kcp.value),
        createdBy: values.createdBy.value,
        objectMarking: values.objectMarking.map((om) => om.value),
        externalReferences: values.externalReferences.map((er) => er.value),
      };
      try {
        commitRelationshipCreationMutation({
          variables: { input: finalValues },
          updater: (store: RecordSourceSelectorProxy) => {
            if (paginationOptions) { // view update if in Knowledge tab
              if (connectionKey === 'Pagination_stixCoreRelationships') {
                // Handles 'Relationships View'
                insertNode(
                  store,
                  connectionKey,
                  paginationOptions,
                  'stixCoreRelationshipAdd',
                );
              } else if (typeof onCreate !== 'function') {
                // Handle 'Entities View'
                insertNode(
                  store,
                  connectionKey || 'Pagination_stixCoreRelationships',
                  paginationOptions,
                  'stixCoreRelationshipAdd',
                  null,
                  null,
                  null,
                  reversed ? 'from' : 'to',
                );
              }
            }
          },
          onError: (error: Error) => {
            handleErrorInForm(error);
          },
          onCompleted: () => {
            setSubmitting(false);
            resetForm();
            handleClose();
            if (typeof onCreate === 'function') {
              onCreate();
            }
          },
        });
      } catch (error) {
        setSubmitting(false);
        handleErrorInForm(error, setErrors);
      }
    }
  };

  return (
    <UserContext.Consumer>
      {({ schema }) => {
        const relationshipTypes = resolveRelationsTypes(
          fromEntities[0].entity_type,
          toEntities[0].entity_type,
          schema?.schemaRelationsTypesMapping ?? new Map(),
        ).filter( // Unique filter
          (value, index, self) => self.indexOf(value) === index,
        ).filter(
          (n) => !allowedRelationshipTypes
            || allowedRelationshipTypes.length === 0
            || allowedRelationshipTypes.includes('stix-core-relationship')
            || allowedRelationshipTypes.includes(n),
        );
        return (
          <StixCoreRelationshipCreationForm
            fromEntities={fromEntities}
            toEntities={toEntities}
            relationshipTypes={relationshipTypes}
            handleReverseRelation={handleReverseRelation}
            handleResetSelection={handleResetSelection}
            onSubmit={onSubmit}
            handleClose={handleClose}
            defaultStartTime={(new Date()).toISOString()}
            defaultStopTime={(new Date()).toISOString()}
            defaultConfidence={undefined}
            defaultCreatedBy={undefined}
            defaultMarkingDefinitions={undefined}
          />
        );
      }}
    </UserContext.Consumer>
  );
};

export default StixCoreRelationshipCreationFormStage;
