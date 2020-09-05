var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');

var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var config = require('./config.js');

// local strategy is used with user login
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser())

// creates the JWT token based on user information
exports.getToken = function (user) {
    return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

// JWT stragegy based passport user authentication, 
// which first extracts the jwt payload from the request header and
// then gets user data from payload and checks if it's present in db 
exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({ _id: jwt_payload._id }, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));

// uses JSON web tokens for token-based user authentication
// passport uses jwt strategy for user authentication    
exports.verifyUser = passport.authenticate('jwt', { session: false });