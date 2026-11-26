import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { Form, Formik, FormikConfig } from 'formik';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { ContainerAddStixCoreObjecstLineDummy, ContainerAddStixCoreObjectsLine } from './ContainerAddStixCoreObjectsLine';
import { addObjectToContainer, removeObjectFromContainer } from './containerObjects';
import CommitMessage from '../form/CommitMessage';
import { ExternalReferencesValues } from '../form/ExternalReferencesField';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ContainerAddStixCoreObjectsLinesQuery } from './__generated__/ContainerAddStixCoreObjectsLinesQuery.graphql';
import { ContainerAddStixCoreObjectsLines_data$key } from './__generated__/ContainerAddStixCoreObjectsLines_data.graphql';

const nbOfRowsToLoad = 50;

export const containerAddStixCoreObjectsLinesRelationAddMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    containerEdit(id: $id) {
      relationAdd(input: $input, commitMessage: $commitMessage, references: $references) {
        id
        to {
          ... on StixDomainObject {
            ...ContainerStixDomainObjectLine_node
          }
          ... on StixCyberObservable {
            ...ContainerStixCyberObservablesLine_node
          }
          ... on StixFile {
            observableName: name
          }
        }
      }
    }
  }
`;

export const containerAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    containerEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type, commitMessage: $commitMessage, references: $references) {
        id
      }
    }
  }
`;

export const containerAddStixCoreObjectsLinesQuery = graphql`
  query ContainerAddStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ContainerAddStixCoreObjectsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const containerAddStixCoreObjectsLinesFragment = graphql`
  fragment ContainerAddStixCoreObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ContainerAddStixCoreObjectsLinesRefetchQuery") {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          id
          standard_id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
          }
          creators {
            id
            name
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...ContainerAddStixCoreObjectsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

// An object of the container, or of the list: the mapping view identifies them by standard_id
interface ToggledObject {
  id: string;
  standard_id?: string;
}

interface ReferencesFormValues {
  message: string;
  references: ExternalReferencesValues;
}

interface ContainerAddStixCoreObjectsLinesProps {
  queryRef: PreloadedQuery<ContainerAddStixCoreObjectsLinesQuery>;
  containerId: string;
  dataColumns: DataColumns;
  // Pagination options of the container's object list, updated in the store when an object is added or removed
  paginationOptions?: Record<string, unknown>;
  knowledgeGraph?: boolean;
  // The objects already in the container
  containerStixCoreObjects?: readonly { node: ToggledObject }[];
  onAdd?: (object: ToggledObject) => void;
  onDelete?: (object: ToggledObject) => void;
  setNumberOfElements?: UseLocalStorageHelpers['handleSetNumberOfElements'];
  enableReferences?: boolean;
  onLabelClick?: HandleAddFilter;
}

const indexById = (containerStixCoreObjects?: readonly { node: ToggledObject }[]) => Object.fromEntries(
  (containerStixCoreObjects ?? []).map(({ node }) => [node.id, node]),
);

const ContainerAddStixCoreObjectsLines: FunctionComponent<ContainerAddStixCoreObjectsLinesProps> = ({
  queryRef,
  containerId,
  dataColumns,
  paginationOptions,
  knowledgeGraph,
  containerStixCoreObjects,
  onAdd,
  onDelete,
  setNumberOfElements,
  enableReferences,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
    ContainerAddStixCoreObjectsLinesQuery,
    ContainerAddStixCoreObjectsLines_data$key
  >({
    linesQuery: containerAddStixCoreObjectsLinesQuery,
    linesFragment: containerAddStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const [referenceDialogOpened, setReferenceDialogOpened] = useState(false);
  const [currentlyToggledCoreObject, setCurrentlyToggledCoreObject] = useState<ToggledObject | null>(null);
  const [addedStixCoreObjects, setAddedStixCoreObjects] = useState<Record<string, ToggledObject>>(
    () => indexById(containerStixCoreObjects),
  );

  // The panel also adds objects (the ones created from it): follow its list
  useEffect(() => {
    setAddedStixCoreObjects(indexById(containerStixCoreObjects));
  }, [containerStixCoreObjects]);

  const sendStixCoreObjectModification = (
    stixCoreObject: ToggledObject,
    commitMessage = '',
    references: string[] = [],
    setSubmitting?: (isSubmitting: boolean) => void,
    resetForm?: () => void,
  ) => {
    const alreadyAdded = stixCoreObject.id in addedStixCoreObjects
      || (!!stixCoreObject.standard_id && stixCoreObject.standard_id in addedStixCoreObjects);
    const args = { containerId, objectId: stixCoreObject.id, knowledgeGraph, paginationOptions, commitMessage, references };
    const markAsAdded = () => setAddedStixCoreObjects((current) => ({ ...current, [stixCoreObject.id]: stixCoreObject }));
    const complete = () => {
      setSubmitting?.(false);
      resetForm?.();
    };
    // The error is already shown by the mutation
    const fail = () => setSubmitting?.(false);
    if (alreadyAdded) {
      removeObjectFromContainer(args).then(() => {
        setAddedStixCoreObjects((current) => {
          const { [stixCoreObject.id]: _, ...rest } = current;
          if (stixCoreObject.standard_id) delete rest[stixCoreObject.standard_id];
          return rest;
        });
        onDelete?.(stixCoreObject);
        complete();
      }).catch(fail);
    } else {
      addObjectToContainer({
        ...args,
        optimisticUpdater: knowledgeGraph ? undefined : markAsAdded,
      }).then(() => {
        if (knowledgeGraph) markAsAdded();
        onAdd?.(stixCoreObject);
        complete();
      }).catch(fail);
    }
  };

  const stixCoreObjectToggled = (stixCoreObject: ToggledObject) => {
    if (enableReferences) {
      setReferenceDialogOpened(true);
      setCurrentlyToggledCoreObject(stixCoreObject);
    } else {
      sendStixCoreObjectModification(stixCoreObject);
    }
  };

  const closeReferencesPopup = () => {
    setReferenceDialogOpened(false);
    setCurrentlyToggledCoreObject(null);
  };

  const submitReference: FormikConfig<ReferencesFormValues>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    if (!currentlyToggledCoreObject) return;
    const references = (values.references ?? []).map((reference) => reference.value);
    sendStixCoreObjectModification(currentlyToggledCoreObject, values.message, references, setSubmitting, () => resetForm());
  };

  const dataList = data?.stixCoreObjects?.edges ?? [];
  // The mapping view gives standard_id, we need to convert
  const computedAddedStixCoreObjects: Record<string, unknown> = {};
  Object.keys(addedStixCoreObjects).forEach((addedId) => {
    const byId = dataList.find((edge) => edge?.node.id === addedId);
    if (byId) {
      computedAddedStixCoreObjects[addedId] = byId;
      return;
    }
    const byStandardId = dataList.find((edge) => edge?.node.standard_id === addedId);
    if (byStandardId) {
      computedAddedStixCoreObjects[byStandardId.node.id] = byStandardId;
    }
  });

  return (
    <>
      <ListLinesContent
        initialLoading={!data}
        loadMore={loadMore}
        hasMore={hasMore}
        isLoading={isLoadingMore}
        dataList={dataList}
        globalCount={data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        onLabelClick={onLabelClick}
        // Components, not elements: the list gives them their props
        LineComponent={ContainerAddStixCoreObjectsLine}
        DummyLineComponent={ContainerAddStixCoreObjecstLineDummy}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        addedElements={computedAddedStixCoreObjects}
        onToggleEntity={stixCoreObjectToggled}
        disableExport={true}
      />
      {enableReferences && (
        <Formik<ReferencesFormValues>
          initialValues={{ message: '', references: [] }}
          onSubmit={submitReference}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
            <Form>
              <CommitMessage
                handleClose={closeReferencesPopup}
                open={referenceDialogOpened}
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                values={values.references}
                id={containerId}
                noStoreUpdate={true}
              />
            </Form>
          )}
        </Formik>
      )}
    </>
  );
};

export default ContainerAddStixCoreObjectsLines;
