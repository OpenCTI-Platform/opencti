import gql from "graphql-tag";
import { describe, expect, it } from "vitest";
import { queryAsAdmin } from "../../utils/testQuery";

const READ_QUERY = gql`
  query persona ($id: String!) {
    stixCyberObservable(id: $id) {
      ... on Persona {
        id
        standard_id
        persona_name
        persona_type
        toStix
      }
    }
  }
`;

describe('Persona StixCyberObservable resolver standard behavior', () => {
  let personaInternalId: string;
  let personaStixId: string;
  const personaName = 'Ice King';
  const personaType = 'moniker';
  it('should create a persona', async () => {
    const CREATE_QUERY = gql`
      mutation PersonaAdd($input: PersonaAddInput) {
        stixCyberObservableAdd(type: "Persona", Persona: $input) {
          ... on Persona {
            id
            standard_id
            persona_name
            persona_type
          }
        }
      }
    `;
    // Create the persona
    const PERSONA_TO_CREATE = {
      input: {
        persona_name: personaName,
        persona_type: personaType,
      },
    };
    const persona = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PERSONA_TO_CREATE,
    });
    expect(persona).not.toBeNull();
    expect(persona.data).not.toBeNull();
    expect(persona.data?.stixCyberObservableAdd).not.toBeNull();
    expect(persona.data?.stixCyberObservableAdd.persona_name).toEqual(personaName);
    expect(persona.data?.stixCyberObservableAdd.persona_type).toEqual(personaType);
    personaInternalId = persona.data?.stixCyberObservableAdd.id;
    personaStixId = persona.data?.stixCyberObservableAdd.standard_id;
  });
  it('should load a persona by internal id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY, 
      variables: {
        id: personaInternalId,
      }
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable.id).toEqual(personaInternalId);
    expect(queryResult.data?.stixCyberObservable.persona_name).toEqual(personaName);
    expect(queryResult.data?.stixCyberObservable.persona_type).toEqual(personaType);
    expect(queryResult.data?.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should load a persona by stix id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY, 
      variables: {
        id: personaStixId,
      }
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable.id).toEqual(personaInternalId);
    expect(queryResult.data?.stixCyberObservable.persona_name).toEqual(personaName);
    expect(queryResult.data?.stixCyberObservable.persona_type).toEqual(personaType);
    expect(queryResult.data?.stixCyberObservable.toStix.length).toBeGreaterThan(5);
  });
  it('should update a persona', async () => {
    const updatedName = 'Icy';
    const updatedType = 'nickname';
    const UPDATE_QUERY = gql`
      mutation PersonaEdit($id: ID!, $input: [EditInput]!) {
        stixCyberObservableEdit(id: $id) {
          fieldPatch(input: $input) {
            ... on Persona {
              id
              persona_name
              persona_type
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: personaInternalId,
        input: [{
          key: 'persona_name',
          value: updatedName,
        }, {
          key: 'persona_type',
          value: updatedType,
        }]
      }
    });
    expect(queryResult.data?.stixCyberObservableEdit.fieldPatch.persona_name).equal(updatedName);
    expect(queryResult.data?.stixCyberObservableEdit.fieldPatch.persona_type).equal(updatedType);
  });
  it('should delete a persona', async () => {
    const DELETE_QUERY = gql`
      mutation PersonaDelete($id: ID!) {
        stixCyberObservableEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the persona
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: personaInternalId },
    });
    // Verify the persona is no longer found
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: {
        id: personaStixId,
      },
    });
    expect(queryResult.data).not.toBeNull();
    expect(queryResult.data?.stixCyberObservable).toBeNull();
  });
});