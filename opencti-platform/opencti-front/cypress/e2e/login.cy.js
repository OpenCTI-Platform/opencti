describe('Authentication', () => {
  beforeEach(function () {
    cy.fixture('users.json').then((user) => {
      this.user = user;
    });
    cy.visit('/');
  });

  it('Can access user data', function () {
    expect(this.user.email).to.equal('rjoyce@darklight.ai');
  });

  it('Prevents login with incorrect credentials', () => {
    cy.contains('Login').click();
    cy.get('input[name=username]').type('wrong@email.com');
    cy.get('input[name=password]').type('notarealpassword');
    cy.get('input[name=login]').click();
    cy.contains('Invalid').should('be.visible');
  });

  it('Can login', function () {
    cy.contains('Login').click();
    cy.get('input[name=username]').type(this.user.email);
    cy.get('input[name=password]').type(this.user.password);
    cy.get('input[name=login]').click();
  });
});
