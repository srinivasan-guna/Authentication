require('dotenv').config() // requiring environment variable for Security purposes
const express = require ("express");
const bodyParser = require ("body-parser");
const ejs = require ("ejs");
const mongoose = require ("mongoose");
const encrypt = require ("mongoose-encryption");

const app = express();

app.use(express.static ("public") );
app.set('view engine','ejs');
app.use(bodyParser.urlencoded ( {extended:true} ) );

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true });

//Creating a new Schema to store user details using Mongoose(MongoDb)
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//Using mongoose encryption to encrypt the Schema
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

/////////////  NOTE: Schema must be encrypted before creating model ///////

//Creating model for the Schema
const User = new mongoose.model("User", userSchema);

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.post("/register", function(req, res){
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  newUser.save(function(err){
    if(err){
      console.log(err);
    }
    else {
      res.render("secrets");
    }
  });
});

app.post("/login", function(req, res){
  const username = req.body.username;
  const password = req.body.password;

  User.findOne( {email: username}, function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        if( foundUser.password == password){
          res.render("secrets");
        }
        else{
          console.log("Invalid Credentials");
        }
      }
    }
});
});



app.listen(3000, function(){
    console.log("Server Started on port 3000");
});
