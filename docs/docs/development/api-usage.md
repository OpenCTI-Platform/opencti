# GraphQL playground (GraphiQL)

The GraphQL playground is an integrated development environment (IDE) provided by OpenCTI for exploring and testing GraphQL APIs. Based on [GraphiQL](https://github.com/graphql/graphiql), it offers a user-friendly interface that allows developers to interactively query the GraphQL schema, experiment with different queries, and visualize the responses.


## Key features

### Interactive querying

The Playground provides a text editor where developers can write GraphQL queries, mutations, and subscriptions. As you type, the Playground offers syntax highlighting, autocompletion, and error checking to aid in query composition.

The pink arrow button run the query. The buttons below respectively enable to prettify the query, merge fragments into the query, and copy the query.

![Playground interactive query](assets/playground-interactive-query.png)

You can also define and use variables in your queries.

![Playground interactive query with variables](assets/playground-variables.png)

### Documentation

Developers can access comprehensive documentation for the GraphQL schema directly within the Playground. This documentation includes descriptions of all available types, fields, and directives, making it easy to understand the data model and construct queries.

![Playground schema](assets/playground-schema.png)

![Playground documentation](assets/playground-documentation.png)

### Query history

The playground keeps track of previously executed queries, allowing developers to revisit and reuse queries from previous sessions. This feature streamlines the development process by eliminating the need to retype complex queries.

![Playground query history](assets/playground-query-history.png)

### Response visualization

Upon executing a query, the playground displays the response data in a structured and readable format. JSON responses are presented in a collapsible tree view, making it easy to navigate nested data structures and inspect individual fields.

![Playground response visualization](assets/playground-response-visualization.png)

## Getting started

To open the GraphQL playground, browse to `https://<your OpenCTI host>/public/graphql`. When the platform runs under a base path (`app:base_path`, for example `/opencti`), the base path comes first: `https://<your OpenCTI host>/opencti/public/graphql`.

This address is the playground page, not the API endpoint. The playground, like any other API client, sends each query to the API endpoint, `https://<your OpenCTI host>/graphql` (after the base path if any), with the `POST` method. The API endpoint answers other methods with `405 Method Not Allowed`, so it does not open in a browser.

The playground runs the queries as the user logged in to the platform in the same browser: log in to OpenCTI first.

!!! note "Playground and introspection settings"

    The playground is available when `app:graphql:playground:enabled` is `true`. This is the default, unless `app:graphql:secure_by_default` is `true`. The playground is never available when the UI is disabled (`app:enabled_ui` is `false`).

    The documentation explorer and the autocompletion read the schema through introspection. When the platform runs in production mode (`NODE_ENV=production`, as in the Docker images), introspection is disabled by default: an administrator allows it by setting `app:graphql:playground:force_disabled_introspection` to `false` (environment variable `APP__GRAPHQL__PLAYGROUND__FORCE_DISABLED_INTROSPECTION`). See the [configuration](../deployment/configuration.md#technical-customization) page.

Then, follow these steps to utilize the playground:

1. Query editor: Write GraphQL queries, mutations, and subscriptions in the text editor. Use syntax highlighting and autocompletion to speed up query composition.
2. Documentation explorer: Access documentation for the GraphQL schema by clicking on the "Docs" tab on the left. Browse types, fields, and descriptions to understand the available data and query syntax.
3. Query history: View and execute previously executed queries from the "History" tab on the top. Reuse queries and experiment with variations without retyping.
4. Response panel: Visualize query responses in the response pane. Expand and collapse sections to navigate complex data structures and inspect individual fields.

### External Resources

For a more in-depth understanding of GraphQL and its usage, consider exploring the following external resources:

- [GraphQL Official Documentation](https://graphql.org/learn/)
- [GraphQL query documentation](https://graphql.org/learn/queries/)
- [How to GraphQL](https://www.howtographql.com/)