exports.is_api = req => req.path.indexOf('/api/') === 0;

exports.unauthenticated = res => res.status(401).json({ message: 'Unauthorized' });