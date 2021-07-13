module.exports = function (app) {
	app.route('/')
		.get((req, res) => {
			res.send({ msg: 'Welcome' });
		});

	app.use('/auth', require('./auth-router'));
	app.use('/user', require('./user-router'));

	app.all('*', (req, res) => {
		res.status(404).send({ msg: 'not found' });
	})
}