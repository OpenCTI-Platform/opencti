import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

interface AddReportInput {
  name: string;
  objects?: string[];
}

const addReportMutation = (input: AddReportInput) => `
  mutation {
    reportAdd(input: {
      name: "${input.name}",
      published: "${new Date().toISOString()}"
      ${input.objects ? `objects: [${input.objects.map((id) => `"${id}"`).join(', ')}]` : ''}
    }) {
      id
    }
  }
`;

export const addReport = async (
  request: APIRequestContext,
  input: AddReportInput,
) => {
  return graphqlQuery(request, addReportMutation(input));
};

const deleteReportMutation = (id: string) => `
  mutation {
    reportEdit(id: "${id}") {
      delete
    }
  }
`;

export const deleteReport = async (
  request: APIRequestContext,
  id: string,
) => {
  return graphqlQuery(request, deleteReportMutation(id));
};
