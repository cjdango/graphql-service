import { createTestClient } from 'apollo-server-testing';
import { ApolloServer, gql } from 'apollo-server-koa';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import request from 'supertest';

import typeDefs from '../src/typedefs';
import resolvers from '../src/resolvers';
import { User } from '../src/models';
import { app } from '../src/app';

const constructServer = (context = {}) =>
  new ApolloServer({
    typeDefs,
    resolvers,
    context,
  });

const GET_USER = gql`
  query getUser($id: ID!) {
    user(id: $id) {
      id
      name
      email
    }
  }
`;

const GET_USERS = gql`
  query {
    users {
      id
      name
      email
    }
  }
`;

const CREATE_USER = gql`
  mutation createUser($email: String!, $name: String, $password: String!) {
    createUser(input: { email: $email, name: $name, password: $password }) {
      id
      email
      name
    }
  }
`;

const UPDATE_PROFILE = gql`
  mutation updateProfile($email: String, $name: String, $password: String) {
    updateProfile(input: { email: $email, name: $name, password: $password }) {
      id
      email
      name
    }
  }
`;

const testUserData = { email: 'testuser@mail.com', name: 'testuser', password: 'testpassword' };

const createUser = () => {
  const server = constructServer();
  const { mutate } = createTestClient(server);
  return mutate({
    mutation: CREATE_USER,
    variables: testUserData,
  });
};

const setupDB = () => {
  beforeAll(async () => {
    return mongoose
      .connect('mongodb://127.0.0.1:27017/test', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        user: 'test',
        pass: 'test',
      })
      .then(() => {
        console.log('successfully connected to the database');
      })
      .catch((err) => {
        console.log('error connecting to the database', err);
        process.exit();
      });
  });

  afterEach(async () => {
    return User.remove({});
  });

  afterAll((done) => {
    mongoose.disconnect(done);
  });
};
describe('Endpoints', () => {
  setupDB();

  describe('POST /api/auth', () => {
    test('should return valid token', async () => {
      await createUser();

      const base64_creds = Buffer.from(`${testUserData.email}:${testUserData.password}`).toString('base64');
      const resp = await request(app.callback()).post('/api/auth').set('Authorization', `Basic ${base64_creds}`).send();

      expect(resp.status).toBe(200);
      expect(resp.body.token).toBeTruthy();
    });
  });

  describe('Queries', () => {
    it('should fetch a user ', async () => {
      const server = constructServer({ auth: true });
      const { query } = createTestClient(server);

      const resCreateUser = await createUser();
      const id = resCreateUser.data.createUser.id;
      const name = resCreateUser.data.createUser.name;
      const email = resCreateUser.data.createUser.email;

      const res = await query({ query: GET_USER, variables: { id } });

      expect(res.data.user.id).toBe(id);
      expect(res.data.user.name).toBe(name);
      expect(res.data.user.email).toBe(email);
    });

    it('should fetch all users', async () => {
      const server = constructServer({ auth: true });
      const { query } = createTestClient(server);

      await createUser();

      const res = await query({ query: GET_USERS });

      expect(Array.isArray(res.data.users)).toBe(true);
      expect(res.data.users.length).toBe(1);
    });
  });

  describe('Mutations', () => {
    it('should create a user', async () => {
      const res = await createUser();

      expect(res.data.createUser.id).toBeTruthy();
      expect(res.data.createUser.name).toBe(testUserData.name);
      expect(res.data.createUser.email).toBe(testUserData.email);
    });

    it('should update a user', async () => {
      const resCreateUser = await createUser();

      const server = constructServer({ auth: { data: { _id: resCreateUser.data.createUser.id } } });
      const { mutate } = createTestClient(server);

      const email = 'new@mail.com';
      const password = 'newpassword';

      const res = await mutate({
        mutation: UPDATE_PROFILE,
        variables: {
          email,
          password,
        },
      });

      const updatedUser = await User.findById(res.data.updateProfile.id);

      expect(res.data.updateProfile.id).toBe(resCreateUser.data.createUser.id);
      expect(res.data.updateProfile.email).toBe(email);
      expect(await bcrypt.compare(password, updatedUser.password)).toBe(true);
    });
  });
});
