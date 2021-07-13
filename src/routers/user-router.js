const app = module.exports = require('express')();

const { changePassword } = require('../actions').user;
const { checkToken } = require('../actions').auth;

app.use(checkToken);

app.post('/change-password', changePassword);