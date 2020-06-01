import koa from 'koa'; // koa@2
import koaRouter from 'koa-router';
import { ApolloServer } from 'apollo-server-koa';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

import typeDefs from './typedefs';
import resolvers from './resolvers';
import { User } from './models';

const app = new koa();
const router = new koaRouter();
const PORT = 3000;

// Connect to database
mongoose
  .connect('mongodb://127.0.0.1:27017/graphql-service', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    user: 'approot',
    pass: 'approot',
  })
  .then(() => {
    console.log('successfully connected to the database');
  })
  .catch((err) => {
    console.log('error connecting to the database', err);
    process.exit();
  });

mongoose.set('useCreateIndex', true);
mongoose.set('useFindAndModify', false);

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
app.listen(PORT);

// the function that sets up the global context for each resolver, using the req
const context = async ({ ctx }) => {
  const authHeader = (ctx.req.headers && ctx.req.headers.authorization) || '';
  const token = authHeader.split(' ')[1];

  let auth = null;

  try {
    auth = jwt.verify(token, 'shared-secret');
  } catch (err) {
    console.log(err);
  }

  return { auth };
};

const server = new ApolloServer({ typeDefs, resolvers, context });
server.applyMiddleware({ app });
