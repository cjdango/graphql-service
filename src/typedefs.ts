import { gql } from 'apollo-server-koa';

export default gql`
  type User {
    id: ID!
    email: String!
    name: String
  }

  input CreateUserInput {
    email: String!
    password: String!
    name: String
  }

  input UpdateProfileInput {
    name: String
    password: String
    email: String
  }

  type Mutation {
    createUser(input: CreateUserInput!): User!
    updateProfile(input: UpdateProfileInput!): User!
  }

  type Query {
    users: [User!]!
    user(id: ID!): User!
  }
`;
