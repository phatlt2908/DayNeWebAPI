const app = module.exports = require('express')();

const { login, register } = require('../actions').auth;

app.post('/login', login);

app.post('/register', register);