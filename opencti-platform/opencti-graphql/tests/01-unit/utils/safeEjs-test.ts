import { describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { render } from 'ejs';
import { safeRender } from '../../../src/utils/safeEjs';
import { safeRender as safeRenderClient } from '../../../src/utils/safeEjs.client';

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
    'ejs with comment': '<%# This is a comment %>Hello <%= user.name %>',
    'ejs with multiple comments': `
      <%# Comment at start %>
      <% if (user) { %>
        <%# Comment in block %>
        <h2><%= user.name %></h2>
      <% } %>
      <%# Comment at end %>
    `,
    'ejs with comment between code': '<% const x = 1; %><%# Comment here %><%= x %>',
    'whitespace slurp with underscore': '  <%_ JSON.stringify(user) _%>  ',
    'whitespace slurp with dash': '  <%- user.name -%>  ',
  }).map(([name, template]) => ({ name, template }));

  it.each(validCases)('safeRender should succeed for "$name" case', ({ template }) => {
    const safeRendered = safeRender(template, data);
    const unsafeRendered = render(template, data);
    expect(safeRendered).toEqual(unsafeRendered);
  });
});

describe('check safeRender Date proxy', () => {
  it('should allow Date.now()', () => {
    const template = '<%= Date.now() %>';
    const result = safeRender(template, {});
    expect(result).toMatch(/^\d+$/);
  });

  it('should allow Date.parse()', () => {
    const template = '<%= Date.parse("2024-01-01") %>';
    const result = safeRender(template, {});
    expect(result).toBe('1704067200000');
  });

  it('should allow Date.UTC()', () => {
    const template = '<%= Date.UTC(2024, 0, 1) %>';
    const result = safeRender(template, {});
    expect(result).toBe('1704067200000');
  });

  it('should allow new Date() with no arguments', () => {
    const template = '<%= new Date() %>';
    const result = safeRender(template, {});
    // Should create a valid date string
    expect(result).toMatch(/^\w{3} \w{3} \d{2} \d{4}/);
  });

  it('should allow new Date() with timestamp', () => {
    const template = '<%= new Date(1704067200000) %>';
    const result = safeRender(template, {});
    expect(result).toContain('2024');
  });

  it('should allow new Date() with date string', () => {
    const template = '<%= new Date("2024-01-01") %>';
    const result = safeRender(template, {});
    expect(result).toContain('2024');
  });

  it('should allow new Date() with multiple arguments', () => {
    const template = '<%= new Date(2024, 0, 1).getFullYear() %>';
    const result = safeRender(template, {});
    expect(result).toBe('2024');
  });

  it('should allow using Date instance methods', () => {
    const template = '<% const d = new Date(2024, 0, 15); %><%= d.getDate() %>';
    const result = safeRender(template, {});
    expect(result).toBe('15');
  });

  it('should allow Date operations in templates', () => {
    const template = `
      <% const now = new Date(); %>
      <% const timestamp = Date.now(); %>
      Year: <%= now.getFullYear() %>
      Timestamp: <%= timestamp %>
    `;
    const result = safeRender(template, {});
    expect(result).toMatch(/Year: \d{4}/);
    expect(result).toMatch(/Timestamp: \d+/);
  });

  it('should prevent access to Date.prototype', () => {
    const template = '<%= Date.prototype %>';
    expect(() => safeRender(template, {})).toThrow();
  });

  it('should prevent access to Date.constructor', () => {
    const template = '<%= Date.constructor %>';
    expect(() => safeRender(template, {})).toThrow();
  });
});

describe('check safeRender with NotificationTool (markdown)', () => {
  it('should render markdown to HTML with useNotificationTool flag', async () => {
    const template = '<%- octi.markdownToHtml(description) %>';
    const data = {
      description: '# Title\n\nThis is **bold** and *italic* text.'
    };
    
    const result = await safeRenderClient(template, data, { useNotificationTool: true });
    
    expect(result).toContain('<h1>Title</h1>');
    expect(result).toContain('<strong>bold</strong>');
    expect(result).toContain('<em>italic</em>');
  });

  it('should handle markdown with lists', async () => {
    const template = '<%- octi.markdownToHtml(content) %>';
    const data = {
      content: '- Item 1\n- Item 2\n- Item 3'
    };
    
    const result = await safeRenderClient(template, data, { useNotificationTool: true });
    
    expect(result).toContain('<ul>');
    expect(result).toContain('<li>Item 1</li>');
    expect(result).toContain('<li>Item 2</li>');
    expect(result).toContain('<li>Item 3</li>');
  });

  it('should handle undefined markdown gracefully', async () => {
    const template = '<%- octi.markdownToHtml(description) || "No description" %>';
    const data = {
      description: undefined
    };
    
    const result = await safeRenderClient(template, data, { useNotificationTool: true });
    
    expect(result).toBe('No description');
  });

  it('should work in complex template with data array', async () => {
    const template = `
      <% data.forEach(function(item) { %>
        <div class="item">
          <h2><%= item.title %></h2>
          <div class="description"><%- octi.markdownToHtml(item.description) %></div>
        </div>
      <% }); %>
    `;
    const data = {
      data: [
        { title: 'Item 1', description: '**Important** information' },
        { title: 'Item 2', description: 'Another *description*' }
      ]
    };
    
    const result = await safeRenderClient(template, data, { useNotificationTool: true });
    
    expect(result).toContain('<h2>Item 1</h2>');
    expect(result).toContain('<strong>Important</strong>');
    expect(result).toContain('<h2>Item 2</h2>');
    expect(result).toContain('<em>description</em>');
  });

  it('should fail when useNotificationTool flag is not set', async () => {
    const template = '<%- octi.markdownToHtml(description) %>';
    const data = {
      description: '# Title'
    };
    
    // Without the flag, octi should not be available
    await expect(
      safeRenderClient(template, data)
    ).rejects.toThrow(/octi/i);
  });
});

describe('check safeRenderClient error handling and worker termination detection', () => {
  it('should report timeout error when rendering takes too long', async () => {
    // Template with infinite loop should timeout
    const template = '<% while(true) {} %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data, { timeout: 100 })
    ).rejects.toThrow(/timeout after 100ms/i);
  });

  it('should preserve worker error when worker fails before timeout', async () => {
    // Template that causes a worker error
    const template = '<%= nonExistentVariable.property %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data, { timeout: 5000 })
    ).rejects.toThrow(/nonExistentVariable/i);
  });

  it('should handle memory limit errors correctly', async () => {
    // Template that tries to allocate too much memory
    const template = '<% const arr = new Array(1000000000).fill("x"); %><%= arr.length %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data, { 
        timeout: 5000,
        resourceLimits: {
          maxOldGenerationSizeMb: 10,
          maxYoungGenerationSizeMb: 5,
          codeRangeSizeMb: 5,
          stackSizeMb: 2,
        }
      })
    ).rejects.toThrow();
  });

  it('should handle syntax errors in template', async () => {
    // Template with syntax error
    const template = '<% const x = ; %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data)
    ).rejects.toThrow();
  });

  it('should preserve error type when worker encounters runtime error', async () => {
    // Template that causes a runtime error (division by zero leads to Infinity, but accessing undefined property causes error)
    const template = '<%= undefined.nonExistentProperty %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data)
    ).rejects.toThrow(/undefined/i);
  });

  it('should handle template with invalid data access gracefully', async () => {
    // Template trying to access undefined deeply nested property
    const template = '<%= data.deep.nested.property.that.does.not.exist %>';
    const data = {};
    
    await expect(
      safeRenderClient(template, data)
    ).rejects.toThrow();
  });

  it('should succeed with valid template and reasonable timeout', async () => {
    const template = '<% for(let i = 0; i < 1000; i++) {} %>Success';
    const data = {};
    
    const result = await safeRenderClient(template, data, { timeout: 5000 });
    expect(result).toBe('Success');
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
      const safeRendered = safeRender(template, data, { useNotificationTool: true });
      const unsafeRendered = render(template, data);
      expect(safeRendered).toEqual(unsafeRendered);
    }
  );
});
