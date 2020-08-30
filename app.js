require('dotenv').config() // requiring environment variable for Security purposes
const express = require ("express");
const bodyParser = require ("body-parser");
const ejs = require ("ejs");
const mongoose = require ("mongoose");
const session = require('express-session');
const passport = require ("passport");
//passportlocalmongoose use = automatically SALTS & HASH the password
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
//This NPM package is reuired to use "findOrCreate" method for GOOGLE authentication
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static ("public") );
app.set('view engine','ejs');
app.use(bodyParser.urlencoded ( {extended:true} ) );

//setting up the session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//initialize the passport package
app.use(passport.initialize());
//ask passport to deal with the session
app.use(passport.session());

//mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connect("mongodb+srv://Admin-Seenu:test123@cluster0.88rdq.mongodb.net/authenticationDB", {useNewUrlParser: true, useUnifiedTopology: true });

mongoose.set('useCreateIndex', true);

//object created from a mongoose.Schema class = need it for encryption
const userSchema = new mongoose.Schema({
  username: {type: String, unique: true}, // values: email address, googleId, facebookId
  password: String,
  provider: String, // values: 'local', 'google', 'facebook'
  email: String,
  secret: Array
});

userSchema.plugin(passportLocalMongoose, {
  usernameField: "username"
});
userSchema.plugin(findOrCreate);
//Creating model for the Schema
const User = new mongoose.model("User", userSchema);

//the passport local configuration
//create a Strategy = will be the local strategy to authenticate users
passport.use(User.createStrategy());

//using their username and password + serialize and deserialize users
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOrCreate(
      { username: profile.id },
      {
        provider: "google",
        email: profile._json.email
      },
      function (err, user) {
        return cb(err, user);
    });
  }
));

//using a new facebook strategy
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        profileFields: ["id", "email"]
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate(
          { username: profile.id },
          {
            provider: "facebook",
            email: profile._json.email
          },
          function (err, user) {
            return cb(err, user);
          }
        );
    }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

  //  /auth/facebook GET route
app.get("/auth/facebook",
    passport.authenticate("facebook", {
      scope: ["email"]
    })
  );

app.get("/auth/facebook/secrets",
    passport.authenticate('facebook', { failureRedirect: "/login" }),
      function(req, res) {
          // Successful authentication, redirect home.
          res.redirect('/secrets');
        });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
  //authenticate user using passport
  if( req.isAuthenticated() ){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if (foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
  }

  else{
    res.redirect("/login");
   }
});

app.get("/submit", function(req, res){
  if( req.isAuthenticated() ){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){

  const submittedSecret = req.body.secret;
  //We need to identify which user submits the secret.Here, Passport stores that user and sends in 'req'
  //The user can be found by simply "console.log(req.user.id);"

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret.push(submittedSecret); //save the submittedSecret to that user's 'secret' field
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req,res){
    req.logout();
    res.redirect('/');
});

app.post("/register", function(req, res){
  const username = req.body.username;
  const password = req.body.password;
  // register() comes from requiring the passportLocalMongoose
  //don't need to create a new user and no direct interaction with mongoose
  User.register({username: username}, password, function(err, user){
    if(err){
      console.log(err);
      //redirect to the register page so the user can try again
      res.redirect("/register");
    }
    else{
        //authenticate the user using passport
        passport.authenticate("local")(req, res, function(){
          User.updateOne(
            {_id: user._id},
            { $set: { provider: "local", email: username } },function(){
              res.redirect("/secrets");
            }
          );
      });
    }
  });

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      //successReturnToOrRedirect & failureRedirect comes from npm connect-ensure-login pack
      passport.authenticate("local",
      { successReturnToOrRedirect: "/secrets", failureRedirect: "/register" }
    )
      (req, res, function(){
        //Callback is needed to run this part of code
    });
  }
  });

});


let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function(){
    console.log("Server Started on port 3000");
});
