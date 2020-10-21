const express = require('express');
let app = express()
let ECT = require('ect')
let path = require('path')
let Discord = require('discord.js')
app.disable('x-powered-by');
app.enable('trust proxy');
const ectRenderer = ECT({ watch: true, root: path.resolve(`./views`), ext: '.ect' });
app.engine('ect', ectRenderer.render);
app.set('view engine', 'ect');
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated() && req.user) return next();
    res.redirect('/auth/discord')
}

const servers  = new Discord.Collection()
servers.set('1', {
    'id':1,
    1:'bah', 
    name: `S${1}`, 
    path: '/', 
    rcon: null, 
    running: true, 
    spies: new Discord.Collection(), 
    online: []
})


var DiscordStrategy = require('passport-discord').Strategy;
let passport = require('passport')
var scopes = ['identify'];
 
passport.use(new DiscordStrategy({
    clientID: '731078310079103017',
    clientSecret: 'E8cdVoH4IV-wVy-EZuNvyKFl10dB2BKL',
    callbackURL: 'https://exp-panel.herokuapp.com',
    scope: scopes
},
function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ discordId: profile.id }, function(err, user) {
        return cb(err, user);
    });
}));


app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', {
    failureRedirect: '/'
}), function(req, res) {
    res.redirect('/secretstuff') // Successful auth
});

app.get('/', (req, res) => {
    res.render('index', { title: 'Home', head: { description: 'Control Panel: home page', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), serverPage: 'console' });
});
app.use('/static', express.static(path.resolve(`./public`)));
app.get('*', (req, res)=>{
console.log(req.url)
});
app.listen(process.env.PORT||80);