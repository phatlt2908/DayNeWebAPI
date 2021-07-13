const pool = require('../../configs/psql-connect');
const authRepo = require('../respository/authme-repo');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../../configs/config');

login = async function (req, res) {
    const loginInfo = req.body;

    // check required
    if (!loginInfo.username || !loginInfo.password) {
        return res.status(400).send({ mes: 'Incomplete information' });
    }

    try {
        // get user by req username
        const userSqlResult = await pool.query(authRepo.GET_USER_BY_USERNAME, [loginInfo.username]);

        // Check exist username
        if (!userSqlResult.rows.length) {
            throw "username is not exist";
        }

        const user = userSqlResult.rows[0];

        // Check password
        const isMatch = bcrypt.compareSync(loginInfo.password, user.password);
        if (!isMatch) {
            throw "password is incorrect";
        }

        let token = jwt.sign(
            {
                username: user.username,
                email: user.email
            },
            config.secret,
            { expiresIn: '24h' }
        );

        let userRes = {
            username: user.username,
            email: user.email
        };

        res.status(200).send({
            user: userRes,
            token: token
        });
    } catch (err) {
        console.error("Login failed: ", err);
        res.status(400).send({ mes: err });
    }
}

register = async function (req, res) {
    try {
        let user = req.body;

        // Check username existed
        const existedUser = await pool.query(authRepo.GET_USER_BY_USERNAME, [user.username]);
        if (existedUser.rows.length) {
            throw "username is existed";
        }

        // Generate regist
        user["regDate"] = new Date().getTime();

        // Generate password
        let salt = bcrypt.genSaltSync(10);
        let hash = bcrypt.hashSync(user.password, salt);
        user.password = hash;

        // Set default world
        user["world"] = config.defaultWorld;

        let queryParams = [
            user.username,
            user.username,
            user.password,
            user.regDate,
            user.regIp,
            user.world,
            user.email
        ];

        pool.query(authRepo.REGISTER_NEW_USER, queryParams);
        res.status(200).send({ mes: "Register successfully" });
    } catch (err) {
        console.error("Can not register new user", err);
        res.status(400).send({ mes: "Can not register new user" });
    }
}

checkToken = function (req, res, next) {
    if (!req.headers['x-access-token'] && !req.headers['authorization']) {
        return res.status(401).send({
            success: false,
            message: 'Missing token'
        });
    }
    let token = req.headers['x-access-token'] || req.headers['authorization'];
    if (token.startsWith('Bearer ')) {
        token = token.slice(7, token.length);
    }
    if (token) {
        jwt.verify(token, config.secret, (err, decoded) => {
            if (err) {
                return res.status(401).send({
                    success: false,
                    message: 'Token is not valid'
                });
            } else {
                req.decoded = decoded;
                next();
            }
        });
    } else {
        res.status(401).send({
            err: "0001",
            message: "Auth token is not supplied"
        });
    }
}

module.exports = {
    login,
    register,
    checkToken
}