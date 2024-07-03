import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { Form, Formik } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { reportKnowledgeGraphMutationRelationDeleteMutation, reportKnowledgeGraphtMutationRelationAddMutation } from '../../analyses/reports/ReportKnowledgeGraphQuery';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ContainerAddStixCoreObjecstLineDummy, ContainerAddStixCoreObjectsLine } from './ContainerAddStixCoreObjectsLine';
import { setNumberOfElements } from '../../../../utils/Number';
import { insertNode } from '../../../../utils/store';
import CommitMessage from '../form/CommitMessage';

const nbOfRowsToLoad = 50;

const styles = (theme) => ({
  container: {
    padding: '20px 0 20px 0',
  },
  heading: {
    fontSize: theme.typography.pxToRem(15),
    flexBasis: '33.33%',
    flexShrink: 0,
  },
  secondaryHeading: {
    fontSize: theme.typography.pxToRem(15),
    color: theme.palette.text.secondary,
  },
  expansionPanelContent: {
    padding: 0,
  },
  list: {
    width: '100%',
  },
  listItem: {
    width: '100%',
  },
  icon: {
    color: theme.palette.primary.main,
  },
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
});

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

class ContainerAddStixCoreObjectsLinesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      referenceDialogOpened: false,
      expandedPanels: {},
      currentlyToggledCoreObject: null,
      addedStixCoreObjects: R.indexBy(
        R.prop('id'),
        (props.containerStixCoreObjects || []).map((n) => n.node),
      ),
    };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCoreObjects',
      this.props.setNumberOfElements.bind(this),
    );
  }

  sendStixCoreObjectModification(stixCoreObject, commitMessage = '', references = [], setSubmitting = null, resetForm = null) {
    const {
      containerId,
      paginationOptions,
      knowledgeGraph,
      onAdd,
      onDelete,
    } = this.props;
    const { addedStixCoreObjects } = this.state;
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
            this.setState({
              addedStixCoreObjects: R.dissoc(
                stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
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
            const id = stixCoreObject.id in addedStixCoreObjects ? stixCoreObject.id : stixCoreObject.standard_id;
            this.setState({
              addedStixCoreObjects: R.dissoc(
                id,
                this.state.addedStixCoreObjects,
              ),
            });
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
            this.setState({
              addedStixCoreObjects: R.dissoc(
                stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
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
  }

  stixCoreObjectToggled(stixCoreObject) {
    const { enableReferences } = this.props;
    if (enableReferences) {
      this.setState({ referenceDialogOpened: true });
      this.setState({ currentlyToggledCoreObject: stixCoreObject });
    } else {
      this.sendStixCoreObjectModification(stixCoreObject);
    }
  }

  closeReferencesPopup() {
    this.setState({ referenceDialogOpened: false });
    this.setState({ currentlyToggledCoreObject: null });
  }

  submitReference(values, { setSubmitting, resetForm }) {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    this.sendStixCoreObjectModification(this.state.currentlyToggledCoreObject, commitMessage, references, setSubmitting, resetForm);
  }

  render() {
    const { initialLoading, dataColumns, relay, containerRef, enableReferences, containerId } = this.props;
    const { addedStixCoreObjects, referenceDialogOpened } = this.state;
    const dataList = R.pathOr([], ['stixCoreObjects', 'edges'], this.props.data);
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
    return (
      <>
        <ListLinesContent
          initialLoading={initialLoading}
          loadMore={relay.loadMore.bind(this)}
          hasMore={relay.hasMore.bind(this)}
          isLoading={relay.isLoading.bind(this)}
          dataList={dataList}
          globalCount={R.pathOr(
            nbOfRowsToLoad,
            ['stixCoreObjects', 'pageInfo', 'globalCount'],
            this.props.data,
          )}
          LineComponent={<ContainerAddStixCoreObjectsLine />}
          DummyLineComponent={<ContainerAddStixCoreObjecstLineDummy />}
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
          addedElements={computedAddedStixCoreObjects}
          onToggleEntity={this.stixCoreObjectToggled.bind(this)}
          disableExport={true}
          containerRef={containerRef}
        />
        {enableReferences && (
          <Formik
            initialValues={{ message: '', references: [] }}
            onSubmit={this.submitReference.bind(this)}
          >
            {({
              submitForm,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <CommitMessage
                  handleClose={this.closeReferencesPopup.bind(this)}
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
  }
}

ContainerAddStixCoreObjectsLinesComponent.propTypes = {
  containerId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  containerStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  mapping: PropTypes.bool,
  containerRef: PropTypes.object,
  enableReferences: PropTypes.bool,
};

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

const ContainerAddStixCoreObjectsLines = createPaginationContainer(
  ContainerAddStixCoreObjectsLinesComponent,
  {
    data: graphql`
      fragment ContainerAddStixCoreObjectsLines_data on Query
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreObjects;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: containerAddStixCoreObjectsLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(ContainerAddStixCoreObjectsLines);
