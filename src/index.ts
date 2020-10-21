import * as bodyparser from 'body-parser';
import * as compression from 'compression';
import * as connectRedis from 'connect-redis';
import * as Discord from 'discord.js';
import * as dotenv from 'dotenv';
import * as ECT from 'ect';
import * as express from 'express';
import * as expressSession from 'express-session';
import * as fs from 'fs-extra';
import * as morgan from 'morgan';
import * as passport from 'passport';
import { Strategy as DiscordStrategy } from 'passport-discord';
import * as path from 'path';
import * as redis from 'redis';
import * as Rcon from 'modern-rcon';
import { spawn } from 'child_process'

import { Request } from 'express';
dotenv.config({ path: '.env' })

// DISCORD
const SCOPES = ['identify'];
const client = new Discord.Client()
let guild: Discord.Guild = null
let adminRole: Discord.Role = null
let moderatorRole: Discord.Role = null
let donatorRole: Discord.Role = null
// REDIS
const RedisStore = connectRedis(expressSession);
const cache = redis.createClient();
const store = expressSession({
  store: new RedisStore({ client: cache, ttl: 7 * 24 * 60 * 60 }),
  secret: 'factorio-manager',
  resave: false,
  saveUninitialized: false,
});
// EXPRESS
const app = express();
app.disable('x-powered-by');
app.enable('trust proxy');
const isAuthenticated = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (req.isAuthenticated() && req.user) return next();
  res.redirect('/auth/discord')
}

const permissionMiddleware = async (req: Request, res, next) => {
  try {
    if (!req.user) next()
    let user = guild.members.get(req.user.id)
    if (!user) user = await guild.fetchMember(req.user.id)
    req.user.ip = req.ip
    if (user.hasPermission('ADMINISTRATOR')) {
      req.user.isManagement = true
      req.user.isAdmin = true
      req.user.isModerator = true
      req.user.isDonator = true
    } else if (adminRole.members.get(user.id)) {
      req.user.isManagement = false
      req.user.isAdmin = true
      req.user.isModerator = true
      req.user.isDonator = true
    } else if (moderatorRole.members.get(user.id)) {
      req.user.isManagement = false
      req.user.isAdmin = false
      req.user.isModerator = true
      req.user.isDonator = true
    } else if (user.id === '144879528475361280') { // BADgamerNL bypass 
      req.user.isManagement = true
      req.user.isAdmin = true
      req.user.isModerator = true
      req.user.isDonator = true
    } else if (donatorRole.members.get(user.id)) {
      req.user.isManagement = false
      req.user.isAdmin = false
      req.user.isModerator = false
      req.user.isDonator = true
    } else {
      req.user.isManagement = false
      req.user.isAdmin = false
      req.user.isModerator = false
      req.user.isDonator = false
    }
    next()
  } catch (error) {
    if (req.user) {
      req.user.isManagement = false
      req.user.isAdmin = false
      req.user.isModerator = false
    }
    next()
  }
}
// TEMPLATE ENGINE
const ectRenderer = ECT({ watch: true, root: path.resolve(`${__dirname}/../views`), ext: '.ect' });
console.log(`Loaded templates folder: ${path.resolve(`${__dirname}/../views`)}`)
// SERVER LOADING
const serverRegex = new RegExp(process.env.SERVER_REGEX)

interface Spy {
  username: string,
  lastSeen: Date
}

interface Server {
  id: string
  name: string
  file: string
  path: string
  rcon: any
  running: boolean
  online: string[]
  spies: Discord.Collection<string, Spy>
}

const servers: Discord.Collection<string, Server> = new Discord.Collection()
fs.readdirSync(process.env.SERVER_DIR, 'utf8')
  .filter((file: string) => serverRegex.test(file))
  .map((file: string) => {
    const id = serverRegex.exec(file)[1];
    servers.set(id, {
      id, file, name: `S${id}`, path: path.join(process.env.SERVER_DIR, file), rcon: null, running: false, spies: new Discord.Collection(), online: []
    })
  })

servers.map((server) => {
  console.log(`Found server: ${JSON.stringify(server)}`)
})

function isRunning(pid): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return e.code === 'EPERM'
  }
}

setInterval(() => {
  servers.map((server) => {
    server.spies.map((spy) => {
      const diff = (new Date().getTime() - spy.lastSeen.getTime()) / 1000
      if (diff > 2) server.spies.delete(spy.username)
    })
    fs.access(path.join(server.path, 'server.pid'), fs.constants.F_OK, (err) => {
      if (err) { server.running = false; return}
      fs.readFile(path.join(server.path, 'server.pid'), 'utf8', (err, data) => {
        if (err) { server.running = false; return}
        server.running = isRunning(data)
      });
    });
    fs.access(path.join(server.path, '/script-output/', 'server-info.json'), fs.constants.F_OK, (err) => {
      if (err) { server.online = []; return}
      fs.readFile(path.join(server.path, '/script-output/', 'server-info.json'), 'utf8', (err, data) => {
        if (err) { server.online = []; return}
        const info = JSON.parse(data)
        if (server.running) {
          //server.online = info.players.online || []
			server.online = []
        } else {
          server.online = []
        }
      });
    });
  })
}, 1000);

interface Permissions {
  isManagement: boolean
  isAdmin: boolean
  isModerator: boolean
  isDonator: Boolean
}

interface Rank {
  name: string;
  editable: string;
}

const ranks: Discord.Collection<string, Rank> = new Discord.Collection()
ranks.set('Root', { name: 'Root', editable: 'Management' })
ranks.set('Owner', { name: 'Owner', editable: 'Management' })
ranks.set('Developer', { name: 'Developer', editable: 'Management' })
ranks.set('Community_Manager', { name: 'Community Manager', editable: 'Management' })
ranks.set('Admin', { name: 'Admin', editable: 'Admin' })
ranks.set('Mod', { name: 'Mod', editable: 'Moderator' })
ranks.set('Donator', { name: 'Donator', editable: 'Moderator' })
ranks.set('Veteran', { name: 'Veteran', editable: 'Moderator' })
ranks.set('Member', { name: 'Member', editable: 'Moderator' })
ranks.set('Regular', { name: 'Regular', editable: 'Moderator' })
ranks.set('Guest', { name: 'Guest', editable: 'Moderator' })
ranks.set('Jail', { name: 'Jail', editable: 'Moderator' })

// MIDDLEWARES
app.use(store);
app.set('view engine', 'ect');
app.engine('ect', ectRenderer.render);
app.use(bodyparser.urlencoded({ extended: true }));
app.use(bodyparser.json());
app.use(morgan('dev', {
  skip: (req, res) => /\/api\/server\/[0-9]+\/tail/.test(req.url) || /\/api\/server\/[0-9]+\/menu-status/.test(req.url)
}));

// AUTHENTICATION
passport.use(new DiscordStrategy({
  clientID: '731078310079103017',
  clientSecret: 'E8cdVoH4IV-wVy-EZuNvyKFl10dB2BKL',
  callbackURL: 'https://discord.com/api/oauth2/authorize',
  scope: SCOPES,
}, (accessToken: any, refreshToken: any, profile: any, done: (err: Error | null, user?: any, info?: any) => void) => {
  process.nextTick(() => done(null, profile));
}));

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/discord', passport.authenticate('discord', { failureRedirect: '/auth/discord' }), permissionMiddleware, (req, res) => res.redirect('/'));

app.use(compression());
app.use('/static', express.static(path.resolve(`${__dirname}/../public`)))

app.get('/', (req, res) => {
  res.render('index', { title: 'Home', head: { description: 'Control Panel: home page', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), serverPage: 'console' });
});

app.get('/sessions', (req, res) => {
  if (!req.user || !req.user.isManagement) return res.redirect('/');
  cache.keys('sess:*', async (err, records) => {
    if (err) return res.redirect('/');
    const promises = records.map((key) => {
      return new Promise<Object>((resolve, reject) => {
        cache.get(key, (err, value) => {
          if (err) return reject(err);
          let data = JSON.parse(value);
          data.key = key;
          resolve(data);
        });
      });
    });
    const sessions = await Promise.all(promises)
    res.render('sessions', { title: 'Sessions', head: { description: 'Control Panel: Sessions page', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), serverPage: 'console', sessions: sessions });
  })
});

app.post('/remsession', (req, res) => {
  if (!req.user.isManagement) return  res.json({ response: null, data: null, error: 'No permissions' })
  const data = req.body.key.trim()
  if (!data) return res.json({ response: null, data, error: 'No key passed' })
  cache.del(data, (err, number) => {
    if (err) return res.json({ response: null, error: 'error deleting'})
    res.json({ response: number })
  })
})

app.get('/server/:id/console', isAuthenticated, permissionMiddleware, (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  res.render('console', { title: `S${server.id} Console`, head: { description: 'Control Panel: Server Console', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), currentServer: server, spies: server.spies.array(), serverPage: 'console' });
});
app.get('/server/:id/banlist', isAuthenticated, permissionMiddleware, (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  res.render('banlist', { title: `S${server.id} Banlist`, head: { description: 'Control Panel: Server Banlist', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), currentServer: server, spies: server.spies.array(), serverPage: 'banlist' });
});
app.get('/server/:id/status', isAuthenticated, permissionMiddleware, (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  res.render('status', { title: `S${server.id} Status`, head: { description: 'Control Panel: Server Status', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), currentServer: server, spies: server.spies.array(), serverPage: 'status' });
});
app.get('/activity/:username/:id', isAuthenticated, permissionMiddleware, (req, res) => {
  const server = req.params.id === 'ALL' ? 'all' : servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  res.render('activity', { title: `Activity`, head: { description: 'Control Panel: Server Player Activity', author: 'ExplosiveGaming' }, user: req.user, servers: servers.array(), currentServer: server, serverPage: 'console', username: req.params.username });
});

app.get('/api/server/:id/menu-status', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  res.json({
    online: server.online,
    spies: server.spies.array(),
    servers: servers.array()
  })
});

app.get('/api/server/:id/tail', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.status(403).send('')
  server.spies.set(req.user.username, { username: req.user.username as string, lastSeen: new Date()})
  const log = path.join(server.path, '/console.log')
  const stat = await fs.stat(log)
  fs.createReadStream(log, { start: stat.size - 10000, end: stat.size })
    .pipe(res);
});

app.post('/api/server/:id/command', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  const data = req.body.data.trim()
  if (!req.user.isManagement) return res.json({ response: null, data, server: server.id, error: 'You dont have the management role' })
  if (!server) return res.json({ response: null, data, server: server.id, error: 'Server not found' })
  if (!data) return res.json({ response: null, data, server: server.id, error: 'No data passed' })
  try {
    const response = await sendCommand(server, data)
    return res.json({ response, data, server: server.id, error: null })
  } catch (error) {
    return res.json({ response: null, data, server: server.id, error: error.message })
  }
});

app.post('/api/server/:id/message', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  const data = req.body.data.trim().replace(/^\/+/, '')
  if (!req.user.isDonator) return res.json({ response: null, data, server: server.id, error: 'You dont have the moderator role' })
  if (!server) return res.json({ response: null, data, server: server.id, error: 'Server not found' })
  if (!data) return res.json({ response: null, data, server: server.id, error: 'No data passed' })
  try {
    const response = await sendCommand(server, `${req.user.username} [${req.user.isManagement ? 'SAdmin' : req.user.isAdmin ? 'Admin' : req.user.isModerator ? 'Mod' : req.user.isDonator ? 'Donator' : 'Guest'}]: ${data}`)
    return res.json({ response, data, server: server.id, error: null })
  } catch (error) {
    return res.json({ response: null, data, server: server.id, error: error.message })
  }
});

app.post('/api/server/:id/ban', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  const username = req.body.username
  const reason = req.body.reason
  const date = req.body.date ? new Date(req.body.date) : new Date()
  if (!req.user.isDonator) return res.json({ response: null, data: req.body, server: server.id, error: 'You dont have the moderator role' })
  if (!server) return res.json({ response: null, data: req.body, server: server.id, error: 'Server not found' })
  if (!username) return res.json({ response: null, data: req.body, server: server.id, error: 'No username passed' })
  if (!reason) return res.json({ response: null, data: req.body, server: server.id, error: 'No reason passed' })
  try {
    const response = await sendBan(server, { username, reason, byUsername: req.user.username })
    return res.json({ response, data: req.body, server: server.id, error: null })
  } catch (error) {
    return res.json({ response: null, data: req.body, server: server.id, error: error.message })
  }
});

app.get('/api/server/:id/ranks', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server || !req.user.isDonator) return res.redirect('/');
  if (req.user.isManagement) return res.json(ranks.array())
  if (req.user.isAdmin) return res.json(ranks.findAll('editable', 'Admin').concat(ranks.findAll('editable', 'Moderator')))
  if (req.user.isModerator) return res.json(ranks.findAll('editable', 'Moderator'))
});

//! code that kinda works not using it because I think the code below this code works better now!
// app.get('/api/server/:id/start', async (req, res) => {
//   const server = servers.get(req.params.id)
//   if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
//   if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
//   execFile(`factorio`, ['START', server.file], (error, stdout, stderr) => {
//     console.log(stdout)
//     return res.json({ error, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
//   })
// });

app.get('/api/server/:id/start', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['start', 'eu-0'+server.id], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/stop', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['stop', 'eu-0'+server.id], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/restart', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['restart', 'eu-0'+server.id], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/reset', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['reset', 'eu-0'+server.id], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/update', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['update', 'eu-0'+server.id, 'latest'], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/sync', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, server: server.id, error: 'You dont have the admin role' })
  if (!server) return res.json({ response: null, server: server.id, error: 'Server not found' })
  const cmd = spawn(`factorio`, ['sync', 'eu-0'+server.id], { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server.id, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/activity/:username/:server', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  let username = req.params.username
  if (!req.user.isAdmin) return res.json({ response: null, error: 'You dont have the admin role' })
  if (!username) return res.json({ response: null, error: 'Username to check activity not found' })
  let args = [username]
  if (server) args.push(server.file)
  const cmd = spawn(`sh /root/memberRequest.sh`, args, { shell: true });
  let stdout: string = '', stderr: string = ''
  cmd.stdout.on('data', (data) => {stdout += data.toString()});
  cmd.stderr.on('data', (data) => {stderr += data.toString()});
  req.connection.on('end', () => {cmd.kill()});
  cmd.on('exit', (code) => {
    return res.json({ error: null, server: server, response: { stdout: stdout.replace(/\[(\d+;)?\d+m/g, ''), stderr: stderr.replace(/\[(\d+;)?\d+m/g, '') }}).end()
  });
});

app.get('/api/server/:id/banlist', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  const location = path.join(server.path, 'banlist.json')
  if (!server) return res.redirect('/');
  try {
    await fs.stat(location)
    const object = await fs.readJSON(location)
    res.json(object)
  } catch (error) {
    res.json([])
  }
});

app.get('/api/server/:id/server-info', async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server) return res.redirect('/');
  const location = path.join(server.path, '/script-output/', 'server-info.json')
  try {
    await fs.stat(location)
    const object = await fs.readJSON(location)
    res.json(object)
  } catch (error) {
    res.json({})
  }
});

app.get('/api/server/:id/server-settings', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server) return res.redirect('/');
  const location = path.join(server.path, '/data/server-settings.json')
  try {
    await fs.stat(location)
    const object = await fs.readJSON(location)
    //!! REMOVING CREDENTIALS FROM SETTINGS FILE
    object['username'] = '***'
    object['password'] = '***'
    object['token'] = '***'
    res.json(object)
  } catch (error) {
    res.json({})
  }
});

app.get('/api/server/:id/map-settings', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server) return res.redirect('/');
  const location = path.join(server.path, '/data/map-settings.json')
  try {
    await fs.stat(location)
    const object = await fs.readJSON(location)
    res.json(object)
  } catch (error) {
    res.json({})
  }
});

app.get('/api/server/:id/map-gen-settings', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!server) return res.redirect('/');
  const location = path.join(server.path, '/data/map-gen-settings.json')
  try {
    await fs.stat(location)
    const object = await fs.readJSON(location)
    res.json(object)
  } catch (error) {
    res.json({})
  }
});

app.get('/api/server/:id/logs', isAuthenticated, permissionMiddleware, async (req, res) => {
  const server = servers.get(req.params.id)
  if (!req.user.isAdmin) return res.json({ response: null, error: 'You dont have the admin role' })
  if (!server) return res.redirect('/');
  fs.readdir(path.resolve(`/opt/console-logs/factorio${server.id}`), async (err, files) => {
    if (err) return res.json([])
    const fileLogs = files.filter((file: string) => /^console\.(.*)\.log$/.test(file)).map((file: string) => file.match(/^console\.(.*)\.log$/))
    const logs = await Promise.all(fileLogs.map(async (match: RegExpMatchArray) => { return { name: match[0], date: match[1], time: match[2], size: (await fs.stat(path.resolve(`/opt/console-logs/factorio${server.id}/${match[0]}`))).size }}))
    return res.json(logs)
  })
});

app.get('/auth/logout', isAuthenticated, permissionMiddleware, (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/auth/user', async (req, res) => {
  res.json(req.user || {})
});

client.login(process.env.DISCORD_BOT_TOKEN)

client.on('ready', () => {
  guild = client.guilds.get(process.env.DISCORD_BOT_GUILD_ID)
  adminRole = guild.roles.get(process.env.DISCORD_ADMIN_ROLE_ID)
  moderatorRole = guild.roles.get(process.env.DISCORD_MODERATOR_ROLE_ID)
  donatorRole = guild.roles.get(process.env.DISCORD_DONATOR_ROLE_ID)
  console.log(`GUILD: ${guild}\tADMIN ${adminRole.name}\tMODERATOR ${moderatorRole.name}\tDONATOR ${donatorRole.name}`)
  console.log('Looping through roles')
  guild.roles.map((role) => {
    console.log(`ID: ${role.id}\tMEMBERS: ${role.members.array().length}\tNAME: ${role.name}`)
  })
  app.listen(Number(process.env.PORT), process.env.HOST);
  console.log(`Listening on port ${process.env.PORT}`);
})

interface Ban {
  byUsername: string
  username: string
  reason: string
  date: Date
}

function sendBan(ser: Server, { username, reason = 'You have been banned without a reason! Please contact an Admin on our discord: discord.explosivegaming.nl', byUsername, date = new Date() }) {
  return new Promise<Ban>(async (resolve, reject) => {
    try {
      const server = servers.get(ser.id)
      const computedReason = `${reason} - ${date.toISOString().slice(0,10)} - ${byUsername}`
      await sendEmbed(server, { title: 'Player Ban', description: 'There was a player banned.', color: 'crit', fields: [ { name: 'Player', value: username, inline: true }, { name: 'By', value: byUsername, inline: true }, { name: 'Reason', value: computedReason, inline: false } ]})
      await sendCommand(server, `/ban ${username} ${computedReason}`)
      resolve({ byUsername, username, reason: computedReason, date})
    } catch (error) {
      reject(error)
    }
  })
}

function sendUnBan(ser: Server, { username, reason = 'You have been unbanned without a reason! Please contact an Admin on our discord: discord.explosivegaming.nl', byUsername, date = new Date() }) {
  return new Promise<Ban>(async (resolve, reject) => {
    try {
      const server = servers.get(ser.id)
      const computedReason = `${reason} - ${date.toISOString().slice(0,10)} - ${byUsername}`
      await sendEmbed(server, { title: 'Player Ban', description: 'There was a player unbanned.', color: 'low', fields: [ { name: 'Player', value: username, inline: true }, { name: 'By', value: byUsername, inline: true }, { name: 'Reason', value: computedReason, inline: false } ]})
      await sendCommand(server, `/ban ${username} ${computedReason}`)
      resolve({ byUsername, username, reason: computedReason, date})
    } catch (error) {
      reject(error)
    }
  })
}

function giveRank(ser: Server, { username, reason = 'You have been unbanned without a reason! Please contact an Admin on our discord: discord.explosivegaming.nl', byUsername, rank, date = new Date() }) {
  return new Promise<Ban>(async (resolve, reject) => {
    try {
      const server = servers.get(ser.id)
      const computedReason = `${reason} - ${date.toISOString().slice(0,10)} - ${byUsername}`
      await sendEmbed(server, { title: 'Player Ban', description: 'There was a player unbanned.', color: 'low', fields: [ { name: 'Player', value: username, inline: true }, { name: 'By', value: byUsername, inline: true }, { name: 'Reason', value: computedReason, inline: false } ]})
      await sendCommand(server, `/ban ${username} ${computedReason}`)
      resolve({ byUsername, username, reason: computedReason, date})
    } catch (error) {
      reject(error)
    }
  })
}

interface EmbedOptions {
  title: string;
  color: string;
  description: string;
  fields: Field[];
}

interface Field {
  name: string;
  inline: boolean;
  value: string;
}

function sendEmbed(server, options: EmbedOptions) {
  return new Promise(async (resolve, reject) => {
    try {
      const command = `/interface Sync.emit_embeded{ title='${options.title}',color=Color.to_hex(defines.text_color.${options.color}),description='${options.description}',${
        options.fields.map(field => {
          return `['${field.name}:']=${field.inline ? `'<<inline>>'..'${field.value}'` : `'${field.value}'`},`
        }).join('')}}`
      const response = await sendCommand(server, command)
      console.log(command)
      resolve()
    } catch (error) {
      reject(error)
    }
  })  
}

function sendCommand(ser: Server, data: string) {
  return new Promise<string>(async (resolve, reject) => {
    try {
      const server = servers.get(ser.id)
      if (!server.rcon) server.rcon = new Rcon(process.env.RCON_HOST, (34229 + (Number(server.id) - 1)), process.env.RCON_PASSWORD)
      await server.rcon.connect()
      const res = await server.rcon.send(data)
      await server.rcon.disconnect()
      resolve(res)
    } catch (error) {
      reject(error)
    }
  });
}


