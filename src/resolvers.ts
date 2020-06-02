import { AuthenticationError } from 'apollo-server-koa';
import bcrypt from 'bcrypt';
import { Types } from 'mongoose';
import { User } from './models';

const validateEmail = (email) => {
  const emailExpression = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

  const isValidEmail = emailExpression.test(String(email).toLowerCase());
  if (!isValidEmail) throw new Error('email not in proper format');
};

export default {
  Query: {
    user: async (_, { id }, { auth }) => {
      if (!auth) throw new AuthenticationError('Must authenticate');
      return User.findById(id);
    },
    users: async (_, __, { auth }) => {
      if (!auth) throw new AuthenticationError('Must authenticate');
      return User.find();
    },
  },
  Mutation: {
    createUser: async (_, { input }, ctx) => {
      validateEmail(input.email);
      const password = await bcrypt.hash(input.password, 5);
      try {
        return await User.create({ ...input, password });
      } catch {
        throw new Error(`User with email '${input.email}' already exists`);
      }
    },
    updateProfile: async (_, { input }, { auth }) => {
      if (!auth) throw new AuthenticationError('Must authenticate');
      if (input.email) validateEmail(input.email);
      if (input.password) input.password = await bcrypt.hash(input.password, 5);

      try {
        return await User.findByIdAndUpdate(auth.data._id, { ...input }, { new: true });
      } catch (error) {
        throw new Error(`User with email '${input.email}' already exists`);
      }
    },
  },
};
