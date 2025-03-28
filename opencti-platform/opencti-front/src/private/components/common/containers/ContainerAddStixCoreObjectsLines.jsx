import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import { Form, Formik } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import { reportKnowledgeGraphMutationRelationDeleteMutation, reportKnowledgeGraphtMutationRelationAddMutation } from '../../analyses/reports/ReportKnowledgeGraphQuery';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ContainerAddStixCoreObjecstLineDummy, ContainerAddStixCoreObjectsLine } from './ContainerAddStixCoreObjectsLine';
import { insertNode } from '../../../../utils/store';
import CommitMessage from '../form/CommitMessage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

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
            ...ContainerStixCyberObservableLine_node
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
    ...ContainerAddStixCoreObjectsLines_fragment
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
  fragment ContainerAddStixCoreObjectsLines_fragment on Query
  @refetchable(queryName: "ContainerAddStixCoreObjectsLinesRefetchQuery")
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) {
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

const ContainerAddStixCoreObjectsLines = ({
  containerId,
  dataColumns,
  paginationOptions,
  knowledgeGraph,
  containerStixCoreObjects,
  onAdd,
  onDelete,
  containerRef,
  enableReferences,
  onLabelClick,
  queryRef,
  setNumberOfElements,
}) => {
  const [referenceDialogOpened, setReferenceDialogOpened] = useState(false);
  const [currentObject, setCurrentObject] = useState();

  const addedStixCoreObjects = R.indexBy(
    R.prop('id'),
    (containerStixCoreObjects || []).map((n) => n.node),
  );

  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
    isLoading,
  } = usePreloadedPaginationFragment({
    linesQuery: containerAddStixCoreObjectsLinesQuery,
    linesFragment: containerAddStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  const sendStixCoreObjectModification = (
    stixCoreObject,
    commitMessage = '',
    references = [],
    setSubmitting = null,
    resetForm = null,
  ) => {
    const alreadyAdded = stixCoreObject.id in addedStixCoreObjects || stixCoreObject.standard_id in addedStixCoreObjects;
    if (alreadyAdded) {
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphMutationRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
            commitMessage,
            references,
          },
          onCompleted: () => {
            // this.setState({
            //   addedStixCoreObjects: R.dissoc(
            //     stixCoreObject.id,
            //     this.state.addedStixCoreObjects,
            //   ),
            // });
            if (typeof onDelete === 'function') {
              onDelete(stixCoreObject);
            }
            if (setSubmitting) setSubmitting(false);
            if (resetForm) resetForm(true);
          },
          setSubmitting,
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
            commitMessage,
            references,
          },
          updater: (store) => {
            // const id = stixCoreObject.id in addedStixCoreObjects ? stixCoreObject.id : stixCoreObject.standard_id;
            // this.setState({
            //   addedStixCoreObjects: R.dissoc(
            //     id,
            //     this.state.addedStixCoreObjects,
            //   ),
            // });
            // ID is not valid pagination options, will be handled better when hooked
            const options = { ...paginationOptions };
            delete options.id;
            delete options.count;
            const conn = ConnectionHandler.getConnection(
              store.get(containerId),
              'Pagination_objects',
              options,
            );
            ConnectionHandler.deleteNode(conn, stixCoreObject.id);
          },
          onCompleted: () => {
            // this.setState({
            //   addedStixCoreObjects: R.dissoc(
            //     stixCoreObject.id,
            //     this.state.addedStixCoreObjects,
            //   ),
            // });
            if (typeof onDelete === 'function') {
              onDelete(stixCoreObject);
            }
            if (setSubmitting) setSubmitting(false);
            if (resetForm) resetForm(true);
          },
          setSubmitting,
        });
      }
    } else {
      const input = {
        toId: stixCoreObject.id,
        relationship_type: 'object',
      };
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationAddMutation,
          variables: {
            id: containerId,
            input,
            commitMessage,
            references,
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: {
                ...this.state.addedStixCoreObjects,
                [stixCoreObject.id]: stixCoreObject,
              },
            });
            if (typeof onAdd === 'function') {
              onAdd(stixCoreObject);
            }
            if (setSubmitting) setSubmitting(false);
            if (resetForm) resetForm(true);
          },
          setSubmitting,
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
          variables: {
            id: containerId,
            input,
            commitMessage,
            references,
          },
          optimisticUpdater: () => {
            this.setState({
              addedStixCoreObjects: {
                ...this.state.addedStixCoreObjects,
                [stixCoreObject.id]: stixCoreObject,
              },
            });
          },
          updater: (store) => {
            // ID is not valid pagination options, will be handled better when hooked
            const options = { ...paginationOptions };
            delete options.id;
            delete options.count;
            insertNode(
              store,
              'Pagination_objects',
              options,
              'containerEdit',
              containerId,
              'relationAdd',
              { input, commitMessage, references },
              'to',
            );
          },
          onCompleted: () => {
            if (typeof onAdd === 'function') {
              onAdd(stixCoreObject);
            }
            if (setSubmitting) setSubmitting(false);
            if (resetForm) resetForm(true);
          },
          setSubmitting,
        });
      }
    }
  };

  const stixCoreObjectToggled = (stixCoreObject) => {
    if (enableReferences) {
      setReferenceDialogOpened(true);
      setCurrentObject(stixCoreObject);
    } else {
      sendStixCoreObjectModification(stixCoreObject);
    }
  };

  const closeReferencesPopup = () => {
    setReferenceDialogOpened(false);
    setCurrentObject(undefined);
  };

  const submitReference = (values, { setSubmitting, resetForm }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    sendStixCoreObjectModification(currentObject, commitMessage, references, setSubmitting, resetForm);
  };

  const dataList = R.pathOr([], ['stixCoreObjects', 'edges'], data);
  const computedAddedStixCoreObjects = {};
  // The mapping view gives standard_id, we need to convert
  Object.keys(addedStixCoreObjects).forEach((addedId) => {
    let object = dataList.find(({ node: { id } }) => addedId === id);
    if (object) {
      computedAddedStixCoreObjects[addedId] = object;
    } else {
      object = dataList.find(({ node: { standard_id } }) => addedId === standard_id);
      if (object) {
        computedAddedStixCoreObjects[object.node.id] = object;
      }
    }
  });

  console.log('c');
  // useEffect(() => {
  //   console.log('ccsv');
  // }, [addedStixCoreObjects]);

  return (
    <>
      <ListLinesContent
        initialLoading={isLoading}
        loadMore={loadMore}
        hasMore={hasMore}
        isLoading={isLoadingMore}
        dataList={dataList}
        globalCount={data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        onLabelClick={onLabelClick}
        LineComponent={<ContainerAddStixCoreObjectsLine />}
        DummyLineComponent={<ContainerAddStixCoreObjecstLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        addedElements={computedAddedStixCoreObjects}
        onToggleEntity={stixCoreObjectToggled}
        disableExport={true}
        containerRef={containerRef}
      />
      {enableReferences && (
        <Formik
          initialValues={{ message: '', references: [] }}
          onSubmit={submitReference}
        >
          {({
            submitForm,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
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

ContainerAddStixCoreObjectsLines.propTypes = {
  containerId: PropTypes.string,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  containerStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  containerRef: PropTypes.object,
  enableReferences: PropTypes.bool,
  onLabelClick: PropTypes.func,
};

export default ContainerAddStixCoreObjectsLines;
