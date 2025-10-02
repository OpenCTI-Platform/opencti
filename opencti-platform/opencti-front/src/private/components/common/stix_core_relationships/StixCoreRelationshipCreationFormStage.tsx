import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CircularProgress } from '@mui/material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityToMutation,
  TargetEntity,
} from './StixCoreRelationshipCreationFromEntity';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import { handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { CreateRelationshipContext } from './CreateRelationshipContextProvider';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

interface StixCoreRelationshipCreationFormStageProps {
  targetEntities: TargetEntity[];
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromEntityQuery, Record<string, unknown>>;
  handleResetSelection: () => void;
  handleClose: () => void;
  defaultStartTime: string;
  defaultStopTime: string;
  entityId: string;
}

const StixCoreRelationshipCreationFormStage: FunctionComponent<StixCoreRelationshipCreationFormStageProps> = ({
  targetEntities,
  queryRef,
  handleResetSelection,
  handleClose,
  defaultStartTime,
  defaultStopTime,
  entityId,
}) => {
  const { stixCoreObject } = usePreloadedQuery(
    stixCoreRelationshipCreationFromEntityQuery,
    queryRef,
  );

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

  if (!stixCoreObject) {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  }

  const sourceEntity: TargetEntity = stixCoreObject;
  const [fromEntities, setFromEntities] = useState<TargetEntity[]>([sourceEntity]);
  const [toEntities, setToEntities] = useState<TargetEntity[]>(targetEntities);
  useEffect(() => {
    if (reversed) {
      setFromEntities(targetEntities);
      setToEntities([sourceEntity]);
    } else {
      setFromEntities([sourceEntity]);
      setToEntities(targetEntities);
    }
  }, [reversed]);

  const onSubmit: FormikConfig<StixCoreRelationshipCreationFromEntityForm>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = reversed ? targetEntity.id : entityId;
      const toEntityId = reversed ? entityId : targetEntity.id;
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
          (n) => allowedRelationshipTypes === null
            || allowedRelationshipTypes === undefined
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
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
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
