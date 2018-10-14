package org.luatix.api.generic;

import com.coxautodev.graphql.tools.GraphQLQueryResolver;

public class About implements GraphQLQueryResolver {

    public String about() {
        return "Welcome to openCTI graphQL API.";
    }
}
