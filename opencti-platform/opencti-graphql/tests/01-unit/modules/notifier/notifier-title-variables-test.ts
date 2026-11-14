import { describe, expect, it } from 'vitest';
import { compileTitleVariables, normalizeEmailSubject, resolveTitleVariablePath } from '../../../../src/modules/notifier/notifier-title-variables';

const data = {
  notification: { name: 'My trigger', trigger_type: 'live' },
  notification_content: [{ title: 'L\'APT & co', events: [{ operation: 'create', message: 'm' }] }],
  data: [{ instance: { name: 'Report A', labels: ['a', 'b'], confidence: 80, revoked: false, nested: { x: 1 }, nullish: null } }, {}],
  user: { user_email: 'a@b.c' },
  platform_uri: 'https://opencti.example.com',
};

describe('resolveTitleVariablePath', () => {
  it('resolves properties and indexes', () => expect(resolveTitleVariablePath(data, 'notification_content[0].events[0].operation')).toBe('create'));
  it('resolves .length', () => expect(resolveTitleVariablePath(data, 'data.length')).toBe('2'));
  it('returns empty for out-of-range index', () => expect(resolveTitleVariablePath(data, 'notification_content[5].title')).toBe(''));
  it('returns empty for missing property and null mid-path', () => {
    expect(resolveTitleVariablePath(data, 'notification.missing')).toBe('');
    expect(resolveTitleVariablePath(data, 'data[0].instance.nullish.x')).toBe('');
  });
  it('renders scalars and arrays of scalars', () => {
    expect(resolveTitleVariablePath(data, 'data[0].instance.confidence')).toBe('80');
    expect(resolveTitleVariablePath(data, 'data[0].instance.revoked')).toBe('false');
    expect(resolveTitleVariablePath(data, 'data[0].instance.labels')).toBe('a, b');
  });
  it('renders objects as empty', () => expect(resolveTitleVariablePath(data, 'data[0].instance.nested')).toBe(''));
  it('rejects forbidden and inherited properties', () => {
    expect(resolveTitleVariablePath(data, 'notification.constructor')).toBe('');
    expect(resolveTitleVariablePath(data, 'notification.__proto__')).toBe('');
    expect(resolveTitleVariablePath(data, 'notification.toString')).toBe('');
  });
});

describe('compileTitleVariables', () => {
  it('replaces known variables by reference', () => {
    const { template, values } = compileTitleVariables('[$notification.name] $notification_content[0].title', data);
    expect(template).toBe('[<%- octi_title_variables[0] %>] <%- octi_title_variables[1] %>');
    expect(values).toEqual(['My trigger', 'L\'APT & co']);
  });
  it('keeps unknown roots literal', () => {
    expect(compileTitleVariables('Cost $100 $foo.bar $name', data)).toEqual({ template: 'Cost $100 $foo.bar $name', values: [] });
  });
  it('keeps the platform data roots literal, except the platform url', () => {
    const title = '$settings.platform_title $doc_uri $url_suffix';
    expect(compileTitleVariables(title, data)).toEqual({ template: title, values: [] });
  });
  it('replaces the platform url', () => {
    expect(compileTitleVariables('From $platform_uri', data)).toEqual({
      template: 'From <%- octi_title_variables[0] %>',
      values: ['https://opencti.example.com'],
    });
  });
  it('does not consume a trailing dot', () => {
    expect(compileTitleVariables('$notification.name.', data).template).toBe('<%- octi_title_variables[0] %>.');
  });
  it('leaves EJS tags untouched', () => {
    const title = '<% if (notification.name === \'$data\') { %>$notification.name<% } %> <%= \'$user.user_email\' %>';
    const { template, values } = compileTitleVariables(title, data);
    expect(template).toBe('<% if (notification.name === \'$data\') { %><%- octi_title_variables[0] %><% } %> <%= \'$user.user_email\' %>');
    expect(values).toEqual(['My trigger']);
  });
  it('treats <%% as literal text and keeps tokenizing after it', () => {
    expect(compileTitleVariables('<%% $notification.name', data).template).toBe('<%% <%- octi_title_variables[0] %>');
  });
  it('does not re-tokenize resolved values', () => {
    const d = { notification: { name: '$user.user_email' }, user: { user_email: 'a@b.c' } };
    expect(compileTitleVariables('$notification.name', d).values).toEqual(['$user.user_email']);
  });
  it('keeps a literal reference to the values array as is', () => {
    expect(compileTitleVariables('$octi_title_variables[0]', data)).toEqual({ template: '$octi_title_variables[0]', values: [] });
  });
  it('returns the title unchanged when there is no variable', () => {
    expect(compileTitleVariables('[live] static', data)).toEqual({ template: '[live] static', values: [] });
  });
});

describe('normalizeEmailSubject', () => {
  it('flattens line terminators, collapses and trims', () => {
    expect(normalizeEmailSubject('\n[live]  X\r\nBcc: evil@x.y  ')).toBe('[live] X Bcc: evil@x.y');
  });
  it('flattens the unicode line separators U+2028, U+2029 and U+0085', () => {
    expect(normalizeEmailSubject('a\u2028b\u2029c\u0085d')).toBe('a b c d');
  });
});
