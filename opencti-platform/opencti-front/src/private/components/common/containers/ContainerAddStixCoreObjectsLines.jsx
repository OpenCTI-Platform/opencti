import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import { Form, Formik } from 'formik';
import inject18n from '../../../../components/i18n';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ContainerAddStixCoreObjecstLineDummy, ContainerAddStixCoreObjectsLine } from './ContainerAddStixCoreObjectsLine';
import { setNumberOfElements } from '../../../../utils/Number';
import { addObjectToContainer, removeObjectFromContainer } from './containerObjects';
import CommitMessage from '../form/CommitMessage';

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
    // The panel also adds objects (the ones created from it): follow its list
    if (prevProps.containerStixCoreObjects !== this.props.containerStixCoreObjects) {
      this.setState({
        addedStixCoreObjects: R.indexBy(
          R.prop('id'),
          (this.props.containerStixCoreObjects || []).map((n) => n.node),
        ),
      });
    }
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
    const args = { containerId, objectId: stixCoreObject.id, knowledgeGraph, paginationOptions, commitMessage, references };
    const markAsAdded = () => this.setState((state) => ({
      addedStixCoreObjects: { ...state.addedStixCoreObjects, [stixCoreObject.id]: stixCoreObject },
    }));
    const complete = () => {
      if (setSubmitting) setSubmitting(false);
      if (resetForm) resetForm(true);
    };
    // The error is already shown by the mutation
    const fail = () => {
      if (setSubmitting) setSubmitting(false);
    };
    if (alreadyAdded) {
      removeObjectFromContainer(args).then(() => {
        this.setState((state) => ({
          addedStixCoreObjects: R.omit([stixCoreObject.id, stixCoreObject.standard_id], state.addedStixCoreObjects),
        }));
        if (typeof onDelete === 'function') {
          onDelete(stixCoreObject);
        }
        complete();
      }).catch(fail);
    } else {
      addObjectToContainer({
        ...args,
        optimisticUpdater: knowledgeGraph ? undefined : markAsAdded,
      }).then(() => {
        if (knowledgeGraph) markAsAdded();
        if (typeof onAdd === 'function') {
          onAdd(stixCoreObject);
        }
        complete();
      }).catch(fail);
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
    const { initialLoading, dataColumns, relay, enableReferences, containerId } = this.props;
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
          globalCount={this.props.data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
          onLabelClick={this.props.onLabelClick}
          LineComponent={<ContainerAddStixCoreObjectsLine />}
          DummyLineComponent={<ContainerAddStixCoreObjecstLineDummy />}
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
          addedElements={computedAddedStixCoreObjects}
          onToggleEntity={this.stixCoreObjectToggled.bind(this)}
          disableExport={true}
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
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  containerStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  mapping: PropTypes.bool,
  enableReferences: PropTypes.bool,
  onLabelClick: PropTypes.func,
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

export default inject18n(ContainerAddStixCoreObjectsLines);
