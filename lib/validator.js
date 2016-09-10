const mongoose = require('mongoose');

exports.is_id = (id) => mongoose.Types.ObjectId.isValid(id);