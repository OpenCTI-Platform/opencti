describe("Authentication page tests", () => {
  it("Prevents visiting app routes when not logged in", () => {
    cy.visit("/orders");
    cy.get(".space-y-4").should("contain", "Email");
    cy.get(".space-y-4").should("contain", "Password");
    cy.get(".space-y-4").should("contain", "Forgot your password?");
  });
  it("Displays login page", () => {
    cy.visit("/");
    cy.url().should("eq", `${Cypress.config().baseUrl}/`);
    cy.get(".space-y-4").should("contain", "Email");
    cy.get(".space-y-4").should("contain", "Password");
    cy.get(".space-y-4").should("contain", "Forgot your password?");
  });
  it("Displays forgot password page", () => {
    cy.visit("/");
    cy.contains("Forgot your password?").click();
    cy.get(".mx-auto").should(
      "contain",
      "Enter your account email to start password reset"
    );
    cy.get(".mx-auto").should("contain", "Email");
    cy.get('[type="submit"]').should("contain", "Password Reset");
    cy.contains("Cancel").click();
    cy.url().should("eq", `${Cypress.config().baseUrl}/`);
  });
});
