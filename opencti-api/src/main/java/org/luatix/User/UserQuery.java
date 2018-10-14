package org.luatix.User;

import com.coxautodev.graphql.tools.GraphQLQueryResolver;

import java.util.ArrayList;
import java.util.List;

public class UserQuery implements GraphQLQueryResolver {

    public User login(String user, String password) {
        User user1 = new User();
        user1.setId(user + " - 1");
        user1.setEmail("toto@toto.com - " + password);
        return user1;
    }

    public User user(String id) {
        User user1 = new User();
        user1.setId("gen - " + id);
        user1.setEmail("titi@titi.com");
        return user1;
    }

    public List<User> users() {
        return new ArrayList<>();
    }
}
