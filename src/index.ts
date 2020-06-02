import mongoose from 'mongoose';
import { app } from './app';

const PORT = 3000;

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

app.listen(PORT);
