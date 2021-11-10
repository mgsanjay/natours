const mongoose = require('mongoose');
const dotenv = require('dotenv');

//Handling uncaught exception
process.on('uncaughtException', (err) => {
  console.log('Uncaught Exception!! Shutting down');
  console.log(err.name, err.message);
  process.exit(1);
});

dotenv.config({ path: './config.env' });
const app = require('./app');

// console.log(process.env);
const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  // .connect(process.env.DATABASE_LOCAL, {
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
  })
  .then(() => console.log('DB connection successful'));

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on the port: ${port}`);
});

//Handling global unhandeled rejections
process.on('unhandledRejection', (err) => {
  console.log('Unhandeled rejection!! Shutting down');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1); //code 0-success, 1-uncaught exception
  });
});

//Heroku shuts down every 24 hours by sending SIGTERM signal
process.on('SIGTERM', () => {
  console.log('SIGTERM RECEIVED. Shutting down gracefully!');
  server.close(() => {
    console.log('Process terminated!');
  });
});
