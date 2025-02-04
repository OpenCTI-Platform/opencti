import { describe, it, expect } from 'vitest';
import { checkAllowedEjsFunctions } from '../../../src/modules/notifier/notifier-domain';
import { DEFAULT_TEAM_DIGEST_MESSAGE, DEFAULT_TEAM_MESSAGE } from '../../../src/modules/notifier/notifier-statics';

describe('EJS pre verifications test', () => {
  it('should initial templates be allowed', async () => {
    // expect to not throw exception.
    checkAllowedEjsFunctions(DEFAULT_TEAM_DIGEST_MESSAGE.notifier_configuration, true);
    checkAllowedEjsFunctions(DEFAULT_TEAM_MESSAGE.notifier_configuration, true);
  });

  it('should some custom templates be allowed', async () => {
    // expect to not throw exception.
    checkAllowedEjsFunctions(`<% data.forEach(function(item, index) { %>
    {
      <% Object.keys(item).forEach(function(key, keyIndex, keys) { %>
        "<%= key %>":
        <% if (Array.isArray(item[key])) { %>
          [
            <% item[key].forEach(function(subItem, subIndex) { %>
              {
                <% Object.keys(subItem).forEach(function(subKey, subKeyIndex, subKeys) { %>
                  "<%= subKey %>": "<%= JSON.stringify(subItem[subKey], null, 2) %>"
                  <% if (subKeyIndex < subKeys.length - 1) { %>, <% } %>
                  <% }); %>
              }
              <% if (subIndex < item[key].length - 1) { %>, <% } %>
              <% }); %>
        ]
          <% } else if (typeof item[key] === 'object' && item[key] !== null) { %>
          {`);
  });

  it('should be forbidden to use functions not in allowed list', async () => {
    expect(() => checkAllowedEjsFunctions('{"random": "<%=myFunction1(content)%>"}')).toThrowError();
    expect(() => checkAllowedEjsFunctions('{"random": "<%=if(anotherForbiddenInside())%>"}')).toThrowError();
    expect(() => checkAllowedEjsFunctions('{"random": "<%= another_Forbidden_Inside(one, two) %>"}')).toThrowError();
    expect(() => checkAllowedEjsFunctions('{"random": "<%=if(thisIsAllowed)%><%=thisIsNotAllowed()%>"}')).toThrowError();
    expect(() => checkAllowedEjsFunctions(
      `
      {"random": "<%=if(thisIsAllowed)%>
      
      <%=thisIsNotAllowed()%>"}
      
      `
    )).toThrowError();
  });

  it('should be forbidden to use forbidden vars', async () => {
    expect(() => checkAllowedEjsFunctions('{"random": "<%=process.env%>"}')).toThrowError();

    expect(() => checkAllowedEjsFunctions(`{"random": "<%=
    const truc = process;
    JSON.stringify(truc.env)
   
    %>"}`)).toThrowError();
  });

  it('should be ok to use parentheses in if', async () => {
    // expect to not throw exception.
    checkAllowedEjsFunctions('{"random": "<%=if((5*3)+(3*5)===15)%>"}');
  });

  it('should work on non ejs', async () => {
    // expect to not throw exception.
    checkAllowedEjsFunctions('');
    checkAllowedEjsFunctions('string without any ejs at all but coucou() function');
  });
});
