import { describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { render } from 'ejs';
import { safeRender } from '../../../src/utils/safeEjs';

const testFilename = fileURLToPath(import.meta.url);

describe('check safeRender on valid cases', () => {
  const data = {
    user: {
      name: 'test',
      getName: () => 'test',
    },
  };

  const validCases = Object.entries({
    'empty script': '',
    'ejs with no script': 'ejs with no script',
    'data access': 'Hello <%= user %> !',
    'data member access': 'Hello <%- user.name -%> !',
    'data function access': 'Hello <%= user.getName() %> !',
    'ejs with control flow': `
      <% if (user) { %>
        <h2><%= user.name %></h2>
        <h2><%= user.getName() %></h2>
      <% } %>
    `,
    'object assign': '<% Object.assign({}, {test: 1}) %>',
  }).map(([name, template]) => ({ name, template }));

  it.each(validCases)('safeRender should succeed for "$name" case', ({ template }) => {
    const safeRendered = safeRender(template, data);
    const unsafeRendered = render(template, data);
    expect(safeRendered).toEqual(unsafeRendered);
  });
});

describe('check safeRender on real files', () => {
  const data = {
    content: [
      {
        events: [
          {
            instance_id: '1234',
            message: 'event message',
          },
        ],
      },
    ],
    data: [
      {
        instance: {
          id: '1234',
          name: 'test instance',
          report_types: ['type1', 'type2'],
          labels: ['lbl1', 'lbl2'],
          description: 'test description',
          published: true,
          content: [],
          events: [
            {
              instance_id: '1234',
              message: 'event message',
            },
          ],
        }
      }
    ],
    notification: {
      name: 'test notification',
      created: Date.now(),
    },
  };

  const fileTestCases = [
    'template-1.html',
    'template-2.html',
    'template-3.html',
    'template-4.html',
    'template-6.json',
    'template-7.json',
  ];

  it.each(fileTestCases.map((name) => ({ name })))(
    'safeRender should succeed for template "$name"',
    async ({ name }) => {
      const templateFile = `${testFilename.substring(0, testFilename.lastIndexOf('.'))}.${name}`;
      const template = await fs.readFile(templateFile, 'utf8');
      const safeRendered = safeRender(template, data);
      const unsafeRendered = render(template, data);
      expect(safeRendered).toEqual(unsafeRendered);
    }
  );
});
