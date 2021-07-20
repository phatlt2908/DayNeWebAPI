const pool = require('../../configs/psql-connect');
const authRepo = require('../respository/authme-repo');
const bcrypt = require('bcrypt');

changePassword = async function (req, res) {
    const request = req.body;

    // check required
    if (!request.username || !request.oldPassword || !request.newPassword) {
        return res.status(400).send({ mes: 'Thông tin nhập không đầy đủ' });
    }

    try {
        // get user by req username
        const userSqlResult = await pool.query(authRepo.GET_USER_BY_USERNAME, [request.username]);

        // Check exist username
        if (!userSqlResult.rows.length) {
            throw "Tài khoản không tồn tại";
        }

        const user = userSqlResult.rows[0];

        // Check password
        const isMatch = bcrypt.compareSync(request.oldPassword, user.password);
        if (!isMatch) {
            throw "Mật khẩu không đúng";
        }

        // Generate new password
        let salt = bcrypt.genSaltSync(10);
        let hash = bcrypt.hashSync(request.newPassword, salt);
        user.password = hash;

        // Update DB
        pool.query(authRepo.UPDATE_PASSWORD, [user.username, user.password]);

        res.status(200).send({ mes: "Change password successfully" });
    } catch (err) {
        console.error("Change password failed: ", err);
        res.status(400).send({ mes: err });
    }
}

module.exports = {
    changePassword
}