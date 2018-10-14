package org.luatix.api.user;

import com.coxautodev.graphql.tools.GraphQLQueryResolver;
import org.luatix.base.Database;
import org.luatix.domain.Message;
import org.luatix.domain.User;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@SuppressWarnings("unused")
public class UserQuery implements GraphQLQueryResolver {

    private Database conn;

    public UserQuery(Database conn) {
        this.conn = conn;
    }

    public User login(String user, String password) {

        Iterable<Message> result = this.conn.session().query(Message.class,"MATCH (n:Message) RETURN n LIMIT 25", Collections.emptyMap());
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
