//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require('body-parser');
const {response} = require ("express");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption")
const session   = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const { Session } = require('express-session');
//OAUTH:
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate  = require("mongoose-findorcreate");

const app = express();
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:true,
   
}));

app.use(passport.initialize());
app.use(passport.session());


//mongoDB connection:
mongoose.connect("mongodb://localhost:27017/usersDb", {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex:true});

//object created from mongoose schema class
const userSchema = new  mongoose.Schema({
    email:String,
    password:String,
    secret:String
});


//***encryption(mongoose-encrypt)
//updates password on studio3T into binary string. hence,its not visible
// userSchema.plugin(encrypt, {secret:process.env.SECRET , encryptedFields: ["password"] });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
   
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  //receive auth code:
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//working of buttons:
app.get("/", function(req,res)
{
 res.render("home");   
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
  );

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res)
{
 res.render("login");   
});

app.get("/register", function(req,res)
{
 res.render("register");   
});

app.get("/submit", function(req,res){
if(req.isAuthenticated()){
    res.render("submit");
}else{
    res.redirect("/login");
}
});

app.get("/logout", function(req,res, next){
    req.logout(function(err) {

        if (err) { return next(err); }
    
        res.redirect('/');
    })
});
app.get("/secrets", function(req, res){
//authenticate if the user is logged in or else redirect to login
User.find({"secret":{$ne : null}}, function(err, foundUsers){
    if(err){
        console.log(err)
    }else{
        res.render("secrets", {userWithSecrets: foundUsers})
    }
})
});

//all this content is included in robo3T after connecting
app.post("/register", function(req, res){

    User.register({
        username:req.body.username}, req.body.password, function(err,user){
            if(err){
                console.log(err);
            }else{
               passport.authenticate("local")(req, res, function(){
            //cookie
            res.redirect("/secrets");
               })
            }
        })
});

app.post("/login", function(req,res){

    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req, res, function(){
                //cookie
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/submit", function(req, res){
const submittedSecret = req.body.secret;

User.findById(req.user.id, function(err, foundUser){
if(err){
    console.log(err);
}else{
    if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
            res.redirect("secrets");
        });
    }
}
});
});
app.listen(3000, function(){
    console.log("server started on locahost:3000")
})