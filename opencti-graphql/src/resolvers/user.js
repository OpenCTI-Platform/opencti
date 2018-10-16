import {addUser, assertAdmin, findAll, findById} from "../domain/user";

// noinspection JSUnusedGlobalSymbols
export const userResolvers = {
    Query: {
        users: (_, {first = 25, offset = 0}, context) => {
            assertAdmin(context.user);
            return findAll(first, offset);
        },
        user: (_, {id}, context) => {
            assertAdmin(context.user);
            return findById(id);
        },
        me: (_, args, context) => {
            return findById(context.user.id);
        },
    },
    Mutation: {
        addUser: (_, {input}, context) => {
            assertAdmin(context.user);
            return addUser(input);
        }
    }
};