import { describe, it, expect } from 'vitest';
import { checkAllowedEjsFunctions } from '../../../src/modules/notifier/notifier-domain';
import { DEFAULT_TEAM_DIGEST_MESSAGE, DEFAULT_TEAM_MESSAGE } from '../../../src/modules/notifier/notifier-statics';

describe('EJS pre verifications test', () => {
  it('should initial templates be allowed', async () => {
    // expect to not throw exception.
    checkAllowedEjsFunctions(DEFAULT_TEAM_DIGEST_MESSAGE.notifier_configuration, true);
    checkAllowedEjsFunctions(DEFAULT_TEAM_MESSAGE.notifier_configuration, true);
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
