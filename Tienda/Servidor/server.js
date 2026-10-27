// servidor de la tienda
require('dotenv').config();
const express = require('express'), oracledb = require('oracledb'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), path = require('path'), crypto = require('crypto');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
oracledb.fetchAsString = [oracledb.CLOB];

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..')));   //
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'tienda-juegos-8.html')));

const PUBLICAS = ['prisma_opiniones_tienda', 'prisma_debate'];            // las ve todo el mundo
const PRIVADAS = ['prisma_deseos', 'prisma_carrito', 'prisma_email'];     // solo las ve su dueño
let pool;

const min = rows => rows.map(r => Object.fromEntries(Object.entries(r).map(([k, v]) => [k.toLowerCase(), v])));
const cut = (s, n) => String(s ?? '').slice(0, n);
const clob = s => ({ type: oracledb.DB_TYPE_CLOB, val: s });

// saber quien es: token de usuario o id de invitado
function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    if (t) req.uid = jwt.verify(t, process.env.JWT_SECRET).uid;
    else if (/^[a-z0-9]{8,40}$/.test(req.headers['x-invitado'] || '')) req.uid = 'g' + req.headers['x-invitado'];
    else return res.status(401).json({ error: 'sin identificar' });
    next();
  } catch (e) { res.status(401).json({ error: 'token no valido' }); }
}

// ---- usuarios ----
app.post('/api/registro', async (req, res) => {
  const { nombre, email, clave } = req.body || {};
  if (!nombre || !/^\S+@\S+\.\S+$/.test(email || '') || (clave || '').length < 6)
    return res.status(400).json({ error: 'datos no validos (clave de 6 o mas)' });
  const c = await pool.getConnection();
  try {
    const id = 'u' + crypto.randomBytes(8).toString('hex');
    await c.execute(`INSERT INTO usuarios (id,nombre,email,clave_hash) VALUES (:i,:n,:e,:h)`,
      { i: id, n: cut(nombre, 60), e: email.toLowerCase(), h: await bcrypt.hash(clave, 10) }, { autoCommit: true });
    res.json({ token: jwt.sign({ uid: id }, process.env.JWT_SECRET, { expiresIn: '30d' }), nombre });
  } catch (e) { res.status(e.errorNum === 1 ? 409 : 500).json({ error: e.errorNum === 1 ? 'ese correo ya existe' : 'bd' }); }
  finally { await c.close(); }
});

app.post('/api/login', async (req, res) => {
  const c = await pool.getConnection();
  try {
    const r = await c.execute(`SELECT id,nombre,clave_hash FROM usuarios WHERE email=:e`, { e: String(req.body.email || '').toLowerCase() });
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(req.body.clave || '', u.CLAVE_HASH))) return res.status(401).json({ error: 'correo o clave incorrectos' });
    res.json({ token: jwt.sign({ uid: u.ID }, process.env.JWT_SECRET, { expiresIn: '30d' }), nombre: u.NOMBRE });
  } catch (e) { res.status(500).json({ error: 'bd' }); } finally { await c.close(); }
});

// ---- leer todo lo que ve esta persona ----
async function leerEstado(uid) {
  const c = await pool.getConnection(), e = {};
  try {
    e.prisma_resenas = min((await c.execute(`SELECT id,juego,estrellas,nombre,texto,fecha FROM resenas ORDER BY fecha DESC`)).rows);
    const ps = min((await c.execute(`SELECT id,fecha,metodo,total,email FROM pedidos WHERE propietario=:u ORDER BY fecha DESC`, { u: uid })).rows);
    for (const p of ps) p.juegos = min((await c.execute(`SELECT titulo,precio,codigo FROM pedido_lineas WHERE pedido_id=:i ORDER BY n`, { i: p.id })).rows);
    e.prisma_pedidos = ps;
    for (const k of PUBLICAS)
      e[k] = (await c.execute(`SELECT datos FROM documentos WHERE coleccion=:k ORDER BY creado DESC`, { k })).rows.map(r => JSON.parse(r.DATOS));
    for (const k of PRIVADAS) {
      const r = (await c.execute(`SELECT datos FROM documentos WHERE coleccion=:k AND id=:u`, { k, u: uid })).rows[0];
      if (r) e[k] = JSON.parse(r.DATOS).v;
    }
    return e;
  } finally { await c.close(); }
}

// borra lo que esta persona tenia y ya no viene en la lista nueva
async function quitarSobrantes(c, tabla, filtro, binds, ids) {
  const r = await c.execute(`SELECT id FROM ${tabla} WHERE ${filtro}`, binds);
  for (const { ID } of r.rows) if (!ids.includes(ID)) await c.execute(`DELETE FROM ${tabla} WHERE id=:i AND ${filtro}`, { ...binds, i: ID });
}

async function guardarEstado(uid, k, v) {
  const c = await pool.getConnection();
  try {
    if (k === 'prisma_resenas') {
      const ids = [];
      for (const r of v) {
        if (!r.id || !(r.estrellas >= 1 && r.estrellas <= 5)) continue;
        ids.push(r.id);
        await c.execute(`MERGE INTO resenas t USING dual ON (t.id=:id)
          WHEN MATCHED THEN UPDATE SET texto=:x WHERE t.propietario=:p
          WHEN NOT MATCHED THEN INSERT (id,propietario,juego,estrellas,nombre,texto,fecha) VALUES (:id,:p,:j,:e,:n,:x,:f)`,
          { id: cut(r.id, 40), p: uid, j: cut(r.juego, 120), e: +r.estrellas, n: cut(r.nombre, 60), x: cut(r.texto, 2000), f: cut(r.fecha, 30) });
      }
      await quitarSobrantes(c, 'resenas', 'propietario=:p', { p: uid }, ids);
    } else if (k === 'prisma_pedidos') {
      const ids = [];
      for (const p of v) {
        ids.push(p.id);
        const ya = await c.execute(`SELECT 1 FROM pedidos WHERE id=:i`, { i: p.id });
        if (ya.rows.length) continue;
        await c.execute(`INSERT INTO pedidos (id,propietario,fecha,metodo,total,email) VALUES (:i,:p,:f,:m,:t,:e)`,
          { i: cut(p.id, 40), p: uid, f: cut(p.fecha, 30), m: cut(p.metodo, 30), t: +p.total, e: cut(p.email, 120) });
        for (const l of p.juegos || [])
          await c.execute(`INSERT INTO pedido_lineas (pedido_id,titulo,precio,codigo) VALUES (:i,:t,:pr,:c)`,
            { i: p.id, t: cut(l.titulo, 120), pr: +l.precio, c: cut(l.codigo, 60) });
      }
      await quitarSobrantes(c, 'pedidos', 'propietario=:p', { p: uid }, ids);
    } else if (PUBLICAS.includes(k)) {
      const ids = [];
      for (const d of v) {
        if (!d.id) continue;
        ids.push(String(d.id));
        await c.execute(`MERGE INTO documentos t USING dual ON (t.coleccion=:k AND t.id=:i)
          WHEN MATCHED THEN UPDATE SET datos=:d
          WHEN NOT MATCHED THEN INSERT (coleccion,id,propietario,datos) VALUES (:k,:i,:p,:d)`,
          { k, i: String(d.id), p: uid, d: clob(JSON.stringify(d)) });
      }
      await quitarSobrantes(c, 'documentos', 'coleccion=:k AND propietario=:p', { k, p: uid }, ids);
    } else if (PRIVADAS.includes(k)) {
      await c.execute(`MERGE INTO documentos t USING dual ON (t.coleccion=:k AND t.id=:p)
        WHEN MATCHED THEN UPDATE SET datos=:d
        WHEN NOT MATCHED THEN INSERT (coleccion,id,propietario,datos) VALUES (:k,:p,:p,:d)`,
        { k, p: uid, d: clob(JSON.stringify({ v })) });
    } else throw new Error('clave desconocida');
    await c.commit();
  } catch (e) { await c.rollback(); throw e; } finally { await c.close(); }
}

app.get('/api/estado', auth, async (req, res) => {
  try { res.json(await leerEstado(req.uid)); } catch (e) { console.error(e); res.status(500).json({ error: 'bd' }); }
});
app.put('/api/estado/:clave', auth, async (req, res) => {
  try { await guardarEstado(req.uid, req.params.clave, req.body.valor); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'bd' }); }
});

(async () => {
  // Autonomous Database: se conecta con el wallet (carpeta descomprimida del zip)
  pool = await oracledb.createPool({
    user: process.env.ORACLE_USER,
    password: process.env.ORACLE_PASSWORD,
    connectString: process.env.ORACLE_CONNECT,          // nombre del tnsnames.ora, ej. biblioteca_high
    configDir: process.env.WALLET_DIR,                  // carpeta donde esta tnsnames.ora
    walletLocation: process.env.WALLET_DIR,             // carpeta donde esta ewallet.pem
    walletPassword: process.env.WALLET_PASSWORD         // la clave que pusiste al descargar el wallet
  });
  app.listen(process.env.PORT || 3000, () => console.log('tienda en http://localhost:' + (process.env.PORT || 3000)));
})().catch(e => { console.error('no se pudo conectar a Oracle:', e.message); process.exit(1); });
