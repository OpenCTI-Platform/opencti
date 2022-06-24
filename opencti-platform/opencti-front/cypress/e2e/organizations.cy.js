describe('Organizations', () => {
  beforeEach(() => {
    cy.fixture('users.json').then((user) => {
      cy.visit('/');
      cy.login(user.email, user.password);
      cy.url().should('eq', `${Cypress.config().baseUrl}/dashboard`);
    });
  });

  it('Has a current organization', () => {
    cy.expect('[data-cy="organization"]')
      .to.have.length.of.at.least(1);
  });
});
