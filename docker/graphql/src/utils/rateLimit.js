import createRateLimitDirective from 'graphql-rate-limit';

const GraphQLRateLimit = createRateLimitDirective({
  identifyContext: ctx => {
    return ctx.user && ctx.user.id;
  },
  formatError: ({ fieldName }) => {
    return `Woah there ✋, you are doing way too much ${fieldName}`;
  }
});

export default GraphQLRateLimit;
