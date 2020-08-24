var mongoose = require('mongoose');
var Schema = mongoose.Schema;

// Create schema for the leader
var leaderSchema = new Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    image: {
        type: String,
        required: true
    },
    designation: {
        type: String,
        required: true,
    },
    abbr: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true
    },
    featured: {
      type: Boolean,
      required: false
  }
}, {
    timestamps: true
});

// Create model using the above schema
var Leaders = mongoose.model('Leader', leaderSchema);

module.exports = Leaders;