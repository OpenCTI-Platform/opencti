import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const readData = async (request: APIRequestContext, query: string) => {
  const response = await graphqlQuery(request, query);
  const body = await response.json();
  if (body.errors?.length) {
    throw new Error(`GraphQL error: ${body.errors[0].message}`);
  }
  return body.data;
};

export const addIntrusionSet = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await readData(request, `
    mutation {
      intrusionSetAdd(input: { name: ${JSON.stringify(name)}, description: "Created by the curation end-to-end test" }) {
        id
      }
    }
  `);
  return data.intrusionSetAdd.id;
};

/** Merges the source into the target, as the merge action of the platform does (the merge is recorded, so reversible). */
export const mergeIntrusionSets = async (request: APIRequestContext, targetId: string, sourceId: string) => {
  await readData(request, `
    mutation {
      stixEdit(id: ${JSON.stringify(targetId)}) {
        merge(stixObjectsIds: [${JSON.stringify(sourceId)}]) {
          id
        }
      }
    }
  `);
};

export const intrusionSetExists = async (request: APIRequestContext, id: string): Promise<boolean> => {
  const data = await readData(request, `
    query {
      intrusionSet(id: ${JSON.stringify(id)}) {
        id
      }
    }
  `);
  return !!data.intrusionSet;
};

export const deleteIntrusionSet = async (request: APIRequestContext, id: string) => {
  if (await intrusionSetExists(request, id)) {
    await readData(request, `
      mutation {
        stixDomainObjectEdit(id: ${JSON.stringify(id)}) {
          delete
        }
      }
    `);
  }
};

/** Ids of the open curation proposals the entity is a subject of. */
export const openProposalIds = async (request: APIRequestContext, entityId: string): Promise<string[]> => {
  const data = await readData(request, `
    query {
      curationProposalsForEntity(id: ${JSON.stringify(entityId)}, status: [open]) {
        id
      }
    }
  `);
  return (data.curationProposalsForEntity ?? []).map((proposal: { id: string }) => proposal.id);
};

export const deleteDashboard = async (request: APIRequestContext, id: string) => {
  await graphqlQuery(request, `
    mutation {
      workspaceDelete(id: ${JSON.stringify(id)})
    }
  `);
};
