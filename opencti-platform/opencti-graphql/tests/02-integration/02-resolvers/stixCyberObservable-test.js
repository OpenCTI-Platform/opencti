import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { adminQuery, queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = `
    query stixCyberObservables(
        $first: Int
        $after: ID
        $orderBy: StixCyberObservablesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
    ) {
        stixCyberObservables(
            first: $first
            after: $after
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            search: $search
        ) {
            edges {
                node {
                    id
                    observable_value
                }
            }
        }
    }
`;

// Get an initial qty of current observables for use in expected qty
const queryResultInitial = await queryAsAdmin({ query: gql(LIST_QUERY), variables: { first: 10 } });
let initialCount = 0;
if (queryResultInitial?.data?.stixCyberObservables?.edges?.length) {
  initialCount = queryResultInitial.data.stixCyberObservables.edges.length;
}

const READ_QUERY = gql`
    query stixCyberObservable($id: String!) {
        stixCyberObservable(id: $id) {
            id
            observable_value
            toStix
        }
    }
`;

const observables = {
  credential: {
    observableType: 'credential',
    internalId: null,
    observableValue: 'USA passport 123456789, issued 1/1/2016, expires 1/1/2026',
    createQuery: gql`
      mutation StixCyberObservableAdd($type: String!, $Credential: CredentialAddInput) {
          stixCyberObservableAdd(type: $type, Credential: $Credential) {
              id
              observable_value
              ... on Credential {
                  value
              }
          }
      }`,
    observable() {
      return {
        type: 'Credential',
        Credential: {
          value: this.observableValue,
        },
      };
    },
  },
  ipv4: {
    observableType: 'ipv4',
    internalId: null,
    observableValue: '8.8.8.8',
    stixId: 'ipv4-addr--921c202b-5706-499d-9484-b5cf9bc6f70c',
    createQuery: gql`
      mutation StixCyberObservableAdd($type: String!, $IPv4Addr: IPv4AddrAddInput) {
          stixCyberObservableAdd(type: $type, IPv4Addr: $IPv4Addr) {
              id
              observable_value
              ... on IPv4Addr {
                  value
              }
          }
      }`,
    observable() {
      return {
        type: 'IPv4-Addr',
        stix_id: this.stixId,
        IPv4Addr: {
          value: this.observableValue
        },
      };
    },
  },
  networkTraffic: {
    observableType: 'networkTraffic',
    internalId: null,
    observableValue: 8090,
    createQuery: gql`
    mutation StixCyberObservableAdd($type: String!, $NetworkTraffic: NetworkTrafficAddInput) {
      stixCyberObservableAdd(type: $type, NetworkTraffic: $NetworkTraffic) {
        id
        observable_value
        ... on NetworkTraffic {
          dst_port
        }
      }
    }
  `,
    observable() {
      return {
        type: 'Network-Traffic',
        NetworkTraffic: {
          dst_port: this.observableValue,
        },
      };
    },
  },
  trackingNumber: {
    observableType: 'trackingNumber',
    internalId: null,
    observableValue: '0123 4567 8901 2345 6789 US',
    createQuery: gql`
      mutation StixCyberObservableAdd($type: String!, $TrackingNumber: TrackingNumberAddInput) {
        stixCyberObservableAdd(type: $type, TrackingNumber: $TrackingNumber) {
          id
          observable_value
          ... on TrackingNumber {
            value
          }
        }
      }
    `,
    observable() {
      return {
        type: 'Tracking-Number',
        TrackingNumber: {
          value: this.observableValue,
        },
      };
    },
  },
};

describe.sequential('StixCyberObservable resolver standard behavior', () => {
  it.each(Object.values(observables))('%#. should create $observableType stixCyberObservable with $observableValue value.)', async (observable) => {
    const queryResult = await queryAsAdmin({
      query: observable.createQuery,
      variables: observables[observable.observableType].observable(),
    });
    // eslint-disable-next-line no-param-reassign
    observable.internalId = queryResult.data.stixCyberObservableAdd.id;
    expect(queryResult).not.toBeNull();
    expect(observable.internalId).not.toBeNull();
    expect(queryResult.data.stixCyberObservableAdd).not.toBeNull();
    expect(queryResult.data.stixCyberObservableAdd.observable_value).toEqual(observable.observableValue.toString());
  });
  it.each(Object.values(observables))('%#. should verify with internal id that $observableType stixCyberObservable has been loaded.)', async (observable) => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: observable.internalId } });
    expect(queryResult.data.stixCyberObservable).not.toBeNull();
    expect(queryResult.data.stixCyberObservable.id).toEqual(observable.internalId);
    expect(queryResult.data.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should list stixCyberObservables.', async () => {
    const queryResult = await queryAsAdmin({ query: gql(LIST_QUERY), variables: { first: 10 } });
    // Adds any possible stixCyberObservables present before test started to the quantity added for this specific test
    const resultQty = initialCount + Object.keys(observables).length;
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(resultQty);
  });
  it('should list stixCyberObservables orderBy observable_value.', async () => {
    const queryResult = await adminQuery(LIST_QUERY, { first: 10, orderBy: 'observable_value', orderMode: 'desc' });
    expect(queryResult.data.stixCyberObservables).not.toBeNull();
    // Adds any possible stixCyberObservables present before test started to the quantity added for this specific test
    const resultQty = initialCount + Object.keys(observables).length;
    expect(queryResult.data.stixCyberObservables.edges.length).toEqual(resultQty);
  });
  it.each(Object.values(observables))('%#. should update $observableType stixCyberObservable.)', async (observable) => {
    const UPDATE_QUERY = gql`
        mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
            stixCyberObservableEdit(id: $id) {
                fieldPatch(input: $input) {
                    id
                    x_opencti_score
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: observable.internalId,
        input: { key: 'x_opencti_score', value: '20' },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.fieldPatch.x_opencti_score).toEqual(20);
  });
  it.each(Object.values(observables))('%#. should context patch $observableType stixCyberObservable.)', async (observable) => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation StixCyberObservableEdit($id: ID!, $input: EditContext) {
            stixCyberObservableEdit(id: $id) {
                contextPatch(input: $input) {
                    id
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: observable.internalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixCyberObservableEdit.contextPatch.id).toEqual(observable.internalId);
  });
  it.each(Object.values(observables))('%#. should clean $observableType stixCyberObservable.)', async (observable) => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation StixCyberObservableEdit($id: ID!) {
            stixCyberObservableEdit(id: $id) {
                contextClean {
                    id
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: observable.internalId },
    });
    expect(queryResult.data.stixCyberObservableEdit.contextClean.id).toEqual(observable.internalId);
  });
  it.each(Object.values(observables))('%#. should add relation in $observableType stixCyberObservable.)', async (observable) => {
    const RELATION_ADD_QUERY = gql`
        mutation StixCyberObservableEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
            stixCyberObservableEdit(id: $id) {
                relationAdd(input: $input) {
                    id
                    from {
                        ... on StixCyberObservable {
                    objectMarking {
                        id
                    }
                        }
                    }
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: observable.internalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixCyberObservableEdit).not.toBeNull();
    expect(queryResult.data.stixCyberObservableEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it.each(Object.values(observables))('%#. should delete relation in $observableType stixCyberObservable.)', async (observable) => {
    const RELATION_DELETE_QUERY = gql`
        mutation StixCyberObservableEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            stixCyberObservableEdit(id: $id) {
                relationDelete(toId: $toId, relationship_type: $relationship_type) {
                    id
                    objectMarking {
                        id
                    }
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: observable.internalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.stixCyberObservableEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it.each(Object.values(observables))('%#. should add $observableType stixCyberObservable in note.)', async (observable) => {
    const CREATE_QUERY = gql`
        mutation NoteAdd($input: NoteAddInput!) {
            noteAdd(input: $input) {
                id
                attribute_abstract
                content
            }
        }
    `;
      // Create the note
    const NOTE_TO_CREATE = {
      input: {
        attribute_abstract: 'Note description',
        content: 'Test content',
        objects: [observable.internalId],
        createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
      },
    };
    const note = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: NOTE_TO_CREATE,
    });
    expect(note).not.toBeNull();
    expect(note.data.noteAdd).not.toBeNull();
    expect(note.data.noteAdd.attribute_abstract).toEqual('Note description');
    const noteInternalId = note.data.noteAdd.id;
    const DELETE_QUERY = gql`
        mutation noteDelete($id: ID!) {
            noteEdit(id: $id) {
                delete
            }
        }
    `;
      // Delete the note
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: noteInternalId },
    });
    const READ_NOTE_QUERY = gql`
        query note($id: String!) {
            note(id: $id) {
                id
                standard_id
                attribute_abstract
                content
            }
        }
    `;
      // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_NOTE_QUERY, variables: { id: noteInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.note).toBeNull();
  });
  it.each(Object.values(observables))('%#. should delete $observableType stixCyberObservable.)', async (observable) => {
    const DELETE_QUERY = gql`
          mutation stixCyberObservableDelete($id: ID!) {
              stixCyberObservableEdit(id: $id) {
                  delete
              }
          }
      `;
      // Delete the stixCyberObservable
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: {
        id: observable.internalId
      }
    });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: observable.internalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixCyberObservable).toBeNull();
  });
});
