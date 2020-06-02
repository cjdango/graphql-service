import koa from 'koa'; // koa@2
import koaRouter from 'koa-router';
import { ApolloServer } from 'apollo-server-koa';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';

import typeDefs from './typedefs';
import resolvers from './resolvers';
import { User } from './models';

export const app = new koa();

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: async ({ ctx }) => {
    const authHeader = (ctx.req.headers && ctx.req.headers.authorization) || '';
    const token = authHeader.split(' ')[1];

    let auth = null;

    try {
      auth = jwt.verify(token, 'shared-secret');
    } catch (err) {}

    return { auth };
  },
});

server.applyMiddleware({ app });

const router = new koaRouter();

router.post('/api/auth', async (ctx) => {
  const base64_creds = ctx.header.authorization.split(' ')[1];
  const str_creds = Buffer.from(base64_creds, 'base64').toString();
  const [email, password] = str_creds.split(':');

  const user = await User.findOne({ email });

  if (!user) {
    ctx.throw(401, 'Bad email');
  }

  const { _id, name } = user;

  if (await bcrypt.compare(password, user.password)) {
    ctx.body = {
      token: jwt.sign(
        {
          data: { _id, name, email },
        },
        'shared-secret',
        { expiresIn: '1h' },
      ),
    };
  } else {
    ctx.throw(401, 'Bad password');
  }
});

app.use(router.routes());
app.use(router.allowedMethods());
