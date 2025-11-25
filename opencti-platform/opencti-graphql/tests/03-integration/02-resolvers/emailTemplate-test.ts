import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const READ_TEMPLATE_QUERY = gql`
  query emailTemplate($id: ID!) {
    emailTemplate(id: $id) {
      id
      name
    }
  }
`;

const READ_TEMPLATES_QUERY = gql`
  query emailTemplates($orderMode: OrderingMode) {
    emailTemplates(orderMode: $orderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const CREATE_TEMPLATE_MUTATION = gql`
  mutation emailTemplateAdd($input: EmailTemplateAddInput!) {
    emailTemplateAdd(input: $input) {
      id
      name
    }
  }
`;

const DELETE_TEMPLATE_MUTATION = gql`
  mutation emailTemplateDelete($id: ID!) {
    emailTemplateDelete(id: $id)
  }
`;

const EDIT_TEMPLATE_MUTATION = gql`
  mutation emailTemplateFieldPatch($id: ID!, $input: [EditInput!]!) {
    emailTemplateFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

const generateEmailTemplateToCreate = (value: number) => ({
  name: `emailTemplate${value}`,
  email_object: `email@template${value}.com`,
  sender_email: `sender@email${value}.com`,
  template_body: `templateBody${value}`
});

describe('Email template resolver standard behavior', () => {
  const emailTemplateIds: string[] = [];
  describe('Email template creation', () => {
    it('should create email template', async () => {
      const emailTemplate = await queryAsAdmin({
        query: CREATE_TEMPLATE_MUTATION,
        variables: {
          input: generateEmailTemplateToCreate(1),
        }
      });

      expect(emailTemplate).not.toBeNull();
      expect(emailTemplate.data?.emailTemplateAdd).not.toBeNull();
      expect(emailTemplate.data?.emailTemplateAdd.name).toEqual('emailTemplate1');
      emailTemplateIds.push(emailTemplate.data?.emailTemplateAdd.id);
    });

    it('should create another email template', async () => {
      const emailTemplate = await queryAsAdmin({
        query: CREATE_TEMPLATE_MUTATION,
        variables: {
          input: generateEmailTemplateToCreate(2),
        }
      });

      expect(emailTemplate).not.toBeNull();
      expect(emailTemplate.data?.emailTemplateAdd).not.toBeNull();
      expect(emailTemplate.data?.emailTemplateAdd.name).toEqual('emailTemplate2');
      emailTemplateIds.push(emailTemplate.data?.emailTemplateAdd.id);
    });
  });

  describe('Email template field patch', () => {
    it('should edit the name', async () => {
      if (!emailTemplateIds.length) return;
      const emailTemplate = await queryAsAdmin({
        query: EDIT_TEMPLATE_MUTATION,
        variables: {
          id: emailTemplateIds[0],
          input: [{ key: 'name', value: ['emailTemplate11'] }]
        }
      });

      expect(emailTemplate).not.toBeNull();
      expect(emailTemplate.data?.emailTemplateFieldPatch.name).toEqual('emailTemplate11');
    });
  });

  describe('Email template query', () => {
    it('find one', async () => {
      const emailTemplate = await queryAsAdmin({
        query: READ_TEMPLATE_QUERY,
        variables: {
          id: emailTemplateIds[0],
        }
      });

      expect(emailTemplate).not.toBeNull();
      expect(emailTemplate.data?.emailTemplate).not.toBeNull();
    });

    it('find all', async () => {
      const listResult = await queryAsAdmin({
        query: READ_TEMPLATES_QUERY,
        variables: {
          orderMode: 'desc'
        },
      });

      const emailTemplates = listResult.data?.emailTemplates.edges;
      expect(emailTemplates).not.toBeNull();
      expect(emailTemplates.length).toEqual(2);
    });
  });

  describe('Email template delete', () => {
    it('should delete the first template', async () => {
      await queryAsAdmin({
        query: DELETE_TEMPLATE_MUTATION,
        variables: {
          id: emailTemplateIds[0]
        }
      });

      const emailTemplate = await elLoadById(testContext, ADMIN_USER, emailTemplateIds[0]);
      expect(emailTemplate).not.toBeDefined();
    });

    it('should delete the last template', async () => {
      await queryAsAdmin({
        query: DELETE_TEMPLATE_MUTATION,
        variables: {
          id: emailTemplateIds[1]
        }
      });

      const emailTemplate = await elLoadById(testContext, ADMIN_USER, emailTemplateIds[0]);
      expect(emailTemplate).not.toBeDefined();
    });
  });
});
