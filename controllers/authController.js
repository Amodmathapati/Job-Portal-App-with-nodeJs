import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import userModel from './models/userModel.js';

passport.use(new LocalStrategy({
  usernameField: 'email',  // by default, it's 'username', so we override here
  passwordField: 'password',
}, async (email, password, done) => {
  try {
    const user = await userModel.findOne({ email }).select('+password');
    if (!user) {
      return done(null, false, { message: 'Incorrect email or password.' });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return done(null, false, { message: 'Incorrect email or password.' });
    }
    user.password = undefined;
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// Serialize user to store in session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await userModel.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
