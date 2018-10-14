package org.luatix.servlet;

import graphql.servlet.SimpleGraphQLHttpServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.luatix.OpenCTI.buildSchema;


public class GraphQLEndpoint extends HttpServlet {

    private SimpleGraphQLHttpServlet httpServlet;

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        httpServlet.service(req, resp);
    }

    @Override
    @SuppressWarnings("RedundantThrows")
    public void init() throws ServletException {
        httpServlet = SimpleGraphQLHttpServlet
                .newBuilder(buildSchema())
                .build(); //Add TracingInstrumentation();
    }
/*
    @Override
    protected GraphQLContext createContext(Optional<HttpServletRequest> request, Optional<HttpServletResponse> response) {
        User user = request
                .map(req -> req.getHeader("Authorization"))
                .filter(id -> !id.isEmpty())
                .map(id -> id.replace("Bearer ", ""))
                .map(userRepository::findById)
                .orElse(null);
        return new AuthContext(user, request, response);
    }

    @Override
    protected List<GraphQLError> filterGraphQLErrors(List<GraphQLError> errors) {
        return errors.stream()
                .filter(e -> e instanceof ExceptionWhileDataFetching || super.isClientError(e))
                .map(e -> e instanceof ExceptionWhileDataFetching ? new SanitizedError((ExceptionWhileDataFetching) e) : e)
                .collect(Collectors.toList());
    }
    */
}