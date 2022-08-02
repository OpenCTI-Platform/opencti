describe('Check local setup', () => {
  beforeEach(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
    });
  });

  it('Verify that local credentials are defined', function () {
    assert.isDefined(this.user.email, 'Can load the user email address');
    assert.isDefined(this.user.password, 'Can load the user password');
    cy.visit('/');
  });
});

describe('Test authentication', () => {
  beforeEach(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
    });
    cy.visit('/');
  });

  it('Prevents login with incorrect credentials', () => {
    cy.login('wrong@email.com', 'notarealpassword');
    cy.contains('Invalid').should('be.visible');
  });

  it('Can login and out', function () {
    cy.login(this.user.email, this.user.password);
    cy.logout();
    cy.contains('Login').should('be.visible');
  });
});
