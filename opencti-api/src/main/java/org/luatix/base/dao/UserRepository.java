package org.luatix.base.dao;

import org.luatix.base.Database;
import org.luatix.domain.Message;

import java.util.Collections;

public class UserRepository {

    private final Database base;
    private static UserRepository singleton;

    private UserRepository(Database base) {
        this.base = base;
    }

    public static UserRepository instance(Database base) {
        if(singleton == null) {
            singleton = new UserRepository(base);
        }
        return singleton;
    }

    public void test() {
        Iterable<Message> result = this.base.session() //
                .query(Message.class, "MATCH (n:Message) RETURN n LIMIT 25", Collections.emptyMap());
        System.out.println("find ");
    }
}
