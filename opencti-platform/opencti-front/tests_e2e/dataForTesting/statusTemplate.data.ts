import { APIRequestContext } from '@playwright/test';

export const getStatusTemplates = () => `
  query {
    statusTemplates {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddStatusTemplateInput {
  name: string;
  color: string;
}

const addStatusTemplate = (input: AddStatusTemplateInput) => `
  mutation {
    statusTemplateAdd(input: {
      name: "${input.name}",
      color: "${input.color}",
    }) {
      id
      name
    }
  }
`;

export const addStatusTemplates = async (request: APIRequestContext, statusTemplates: AddStatusTemplateInput[]) => {
  const existingStatusTemplatesResponse = await request.post('/graphql', { data: { query: getStatusTemplates() } });
  const existingStatusTemplatesResponseData = JSON.parse((await existingStatusTemplatesResponse.body()).toString());
  const existingStatusTemplates = existingStatusTemplatesResponseData.data.statusTemplates.edges.map((e: any) => e.node.name);

  await Promise.all(statusTemplates.map(async (statusTemplate) => {
    if (!existingStatusTemplates.includes(statusTemplate.name)) {
      await request.post('/graphql', { data: { query: addStatusTemplate(statusTemplate) } });
    }
  }));
};
