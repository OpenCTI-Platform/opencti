import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CircularProgress } from '@mui/material';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik';
import {
  StixCoreRelationshipCreationFromEntityForm,
  stixCoreRelationshipCreationFromEntityFromMutation,
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityToMutation,
  TargetEntity,
} from './StixCoreRelationshipCreationFromEntity';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import { isNodeInConnection } from '../../../../utils/store';
import { formatDate } from '../../../../utils/Time';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';

interface StixCoreRelationshipCreationFormStageProps {
  targetEntities: TargetEntity[];
  queryRef: PreloadedQuery<StixCoreRelationshipCreationFromEntityQuery, Record<string, unknown>>;
  isRelationReversed?: boolean;
  allowedRelationshipTypes?: string[];
  handleReverseRelation?: () => void;
  handleResetSelection: () => void;
  handleClose: () => void;
  defaultStartTime: string;
  defaultStopTime: string;
  helpers: UseLocalStorageHelpers;
  entityId: string;
  paginationOptions: Record<string, unknown>;
  connectionKey?: string;
  onCreate?: () => void;
}

const StixCoreRelationshipCreationFormStage: FunctionComponent<StixCoreRelationshipCreationFormStageProps> = ({
  targetEntities,
  queryRef,
  isRelationReversed = false,
  allowedRelationshipTypes,
  handleReverseRelation,
  handleResetSelection,
  handleClose,
  defaultStartTime,
  defaultStopTime,
  helpers,
  entityId,
  paginationOptions,
  connectionKey,
  onCreate,
}) => {
  const { stixCoreObject } = usePreloadedQuery(
    stixCoreRelationshipCreationFromEntityQuery,
    queryRef,
  );

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
  let fromEntities = [sourceEntity];
  let toEntities = targetEntities;
  if (isRelationReversed) {
    fromEntities = targetEntities;
    toEntities = [sourceEntity];
  }

  const commit = (finalValues: object) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: isRelationReversed
          ? stixCoreRelationshipCreationFromEntityToMutation
          : stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        updater: (store: RecordSourceSelectorProxy) => {
          if (typeof onCreate !== 'function') {
            const userProxy = store.get(store.getRoot().getDataID());
            const payload = store.getRootField('stixCoreRelationshipAdd');

            const createdNode = connectionKey && payload !== null
              ? payload.getLinkedRecord(isRelationReversed ? 'from' : 'to')
              : payload;
            const connKey = connectionKey || 'Pagination_stixCoreRelationships';
            let conn;
            // When using connectionKey we use less props of PaginationOptions (ex: count),
            // we need to filter them to prevent getConnection to fail
            const { count: _, ...options } = paginationOptions;

            if (userProxy) {
              conn = ConnectionHandler.getConnection(
                userProxy,
                connKey,
                options,
              );
            }

            if (conn && payload !== null
              && !isNodeInConnection(payload, conn)
              && !isNodeInConnection(payload.getLinkedRecord(isRelationReversed ? 'from' : 'to'), conn)
            ) {
              const newEdge = payload.setLinkedRecord(createdNode, 'node');
              ConnectionHandler.insertEdgeBefore(conn, newEdge);

              helpers.handleSetNumberOfElements({ });
            }
          }
        },
        optimisticUpdater: undefined,
        setSubmitting: undefined,
        optimisticResponse: undefined,
        onError: (error: Error) => {
          reject(error);
        },
        onCompleted: (response: Response) => {
          resolve(response);
        },
      });
    });
  };
  const onSubmit: FormikConfig<StixCoreRelationshipCreationFromEntityForm>['onSubmit'] = async (values, { setSubmitting, setErrors, resetForm }) => {
    setSubmitting(true);
    for (const targetEntity of targetEntities) {
      const fromEntityId = isRelationReversed ? targetEntity.id : entityId;
      const toEntityId = isRelationReversed ? entityId : targetEntity.id;
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
        // eslint-disable-next-line no-await-in-loop
        await commit(finalValues);
      } catch (error) {
        setSubmitting(false);
        return handleErrorInForm(error, setErrors);
      }
    }
    setSubmitting(false);
    resetForm();
    handleClose();
    if (typeof onCreate === 'function') {
      onCreate();
    }
    return true;
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
