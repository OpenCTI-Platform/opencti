describe('Organizations', () => {
  before(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
      cy.visit('/');
      cy.login(user.email, user.password);
    });
  });

  beforeEach(() => {
    Cypress.Cookies.preserveOnce('token', 'client_id');
  });

  it('Has a current organization', () => {
    cy.expect('[data-cy="organization"]')
      .to.have.length.of.at.least(1);
  });

  it('Can view the list of organizations to switch to', () => {
    cy.get('[data-cy="organization"]').click();
    cy.get('[data-cy="org selection"]').should('be.visible');
    cy.get('[data-cy="org selection"]').click();
    cy.get('[data-cy="an org"]').should('be.visible');
  });
});
