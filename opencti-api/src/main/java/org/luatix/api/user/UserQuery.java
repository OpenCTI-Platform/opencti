package org.luatix.api.user;

import com.coxautodev.graphql.tools.GraphQLQueryResolver;
import org.luatix.AppContext;
import org.luatix.base.Database;
import org.luatix.base.dao.UserRepository;
import org.luatix.domain.User;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("unused")
public class UserQuery implements GraphQLQueryResolver {

    private UserRepository userRepository;

    public UserQuery() {
        this.userRepository = AppContext.context().database().userRepository();
    }

    public User login(String user, String password) {
        this.userRepository.test();
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
