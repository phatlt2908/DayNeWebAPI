module.exports = {
    REGISTER_NEW_USER: "INSERT INTO authme (username, realname, password, regdate, regip, world, email) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    GET_USER_BY_USERNAME: "SELECT authme.* FROM authme WHERE authme.username = $1",
    UPDATE_PASSWORD: "UPDATE authme SET password = $2 WHERE username = $1"
}