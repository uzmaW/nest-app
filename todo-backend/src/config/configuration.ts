export default () => ({
    port: parseInt(process.env.PORT, 10) || 3000,
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT, 10) || 5432,
        username: process.env.DB_USERNAME || 'postgres',
        password: process.env.DB_PASSWORD || 'postgress',
        database: process.env.DB_NAME || 'nest_todos',
      },
    // database: {
    //   type: 'sqlite',
    //   database: process.env.DB_FILE || 'todos.db',
    // },
    jwt: {
      secret: process.env.JWT_SECRET || 'supersecret',
      expiresIn: '1h',
      refreshExpiresIn: 2592000, // 30 days
    },
  });