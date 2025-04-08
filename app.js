require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const app = express();
const crypto = require('crypto');

app.use(bodyParser.urlencoded({extended: true, limit: '1mb', parameterLimit: 50000, 
    verify: (req, res, buf, encoding) => {
        if (buf.length > 500000) { 
            throw new Error('Payload demasiado grande');
        }
    }
}));

app.use(bodyParser.json({ limit: '1mb',
    verify: (req, res, buf, encoding) => {
        if (buf.length > 500000) { 
            throw new Error('Payload demasiado grande');
        }
    }
}));

const serviceAccount = {
    "type": process.env.FIREBASE_TYPE || "service_account",
    "project_id": process.env.FIREBASE_PROJECT_ID,
    "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
    "private_key": process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
    "client_email": process.env.FIREBASE_CLIENT_EMAIL,
    "client_id": process.env.FIREBASE_CLIENT_ID,
    "auth_uri": process.env.FIREBASE_AUTH_URI,
    "token_uri": process.env.FIREBASE_TOKEN_URI,
    "auth_provider_x509_cert_url": process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
    "client_x509_cert_url": process.env.FIREBASE_CLIENT_CERT_URL,
    "universe_domain": process.env.FIREBASE_UNIVERSE_DOMAIN || "googleapis.com"
};

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const personajesCollection = db.collection('personajes');
const usuariosCollection = db.collection('usuarios');
const { FirestoreStore } = require('@google-cloud/connect-firestore');

// Función para generar hash de contraseñas
function hashPassword(password, salt) {
    if (!salt) {
        salt = crypto.randomBytes(16).toString('hex');
    }
    
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    
    return {
        hash,
        salt
    };
}

// Función para verificar contraseñas
function verifyPassword(password, hash, salt) {
    const hashVerify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === hashVerify;
} 

// Middleware para proteger rutas
function requireLogin(req, res, next) {
    if (!req.session || !req.session.usuarioId) {
        return res.redirect('/login');
    }
    next();
}

// Función para validar datos de registro e inicio de sesión
function validarUsuario(datos, esRegistro = true) {
    const errores = [];
    const { nombre, email, password, confirmPassword } = datos;
    
    const MAX_INPUT_LENGTH = 100;
    
    // Validar email
    if (!email || email.trim() === '') {
        errores.push('El email es obligatorio');
    } else if (email.length > MAX_INPUT_LENGTH) {
        errores.push(`El email no debe exceder ${MAX_INPUT_LENGTH} caracteres`);
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errores.push('El formato del email no es válido');
    }
    
    // Validar contraseña
    if (!password || password.trim() === '') {
        errores.push('La contraseña es obligatoria');
    } else if (password.length < 6) {
        errores.push('La contraseña debe tener al menos 6 caracteres');
    } else if (password.length > MAX_INPUT_LENGTH) {
        errores.push(`La contraseña no debe exceder ${MAX_INPUT_LENGTH} caracteres`);
    }
    
    // Validaciones adicionales solo para registro
    if (esRegistro) {
        // Validar nombre
        if (!nombre || nombre.trim() === '') {
            errores.push('El nombre es obligatorio');
        } else if (nombre.length > MAX_INPUT_LENGTH) {
            errores.push(`El nombre no debe exceder ${MAX_INPUT_LENGTH} caracteres`);
        }
        
        // Validar confirmación de contraseña
        if (!confirmPassword || confirmPassword.trim() === '') {
            errores.push('La confirmación de contraseña es obligatoria');
        } else if (confirmPassword !== password) {
            errores.push('Las contraseñas no coinciden');
        }
    }
    
    // Validar contra inyección NoSQL y otros ataques
    const contieneScript = (texto) => {
        return /<script[\s\S]*?>|javascript:|on\w+\s*=|eval\(|new Function\(|document\.cookie/i.test(texto);
    };
    
    const contieneCaracteresPeligrosos = (texto) => {
        return /[\u0000-\u001F\u007F-\u009F\u2000-\u200F\uFEFF]|[{}\[\]]/i.test(texto);
    };
    
    const contieneTags = (texto) => {
        return /<\/?[a-z][\s\S]*>/i.test(texto) || /<[a-z]+\s*$/i.test(texto) || /^\s*>[^<]*$/i.test(texto);       
    };

    const contieneInyeccionSQL = (texto) => {
        return /(\b(select|insert|update|delete|drop|alter|create|exec|union|where)\b.*\b(from|into|table|database|values)\b)|(-{2,}|\/\*|\*\/|;.*;|@{2}|char\s*\(\s*\d+\s*\)|convert\s*\(|declare\s+@|set\s+@|exec\s+\(|xp_|sp_|waitfor\s+delay)/i.test(texto);
    };
    
    const camposTexto = { nombre, email, password };
    
    for (const [campo, valor] of Object.entries(camposTexto)) {
        if (typeof valor === 'string') {
            if (contieneTags(valor)) {
                errores.push(`El campo ${campo} contiene etiquetas HTML no permitidas`);
            }
            if (contieneScript(valor)) {
                errores.push(`El campo ${campo} contiene código JavaScript no permitido`);
            }
            if (contieneCaracteresPeligrosos(valor)) {
                errores.push(`El campo ${campo} contiene caracteres de control no permitidos`);
            }
            if (contieneInyeccionSQL(valor)) {
                errores.push(`El campo ${campo} contiene patrones de inyección SQL no permitidos`);
            }
        }
    }
    
    return errores;
}

app.use(session({
    store: new FirestoreStore({
        dataset: db,
        kind: 'express-sessions',
    }),
    secret: process.env.SESSION_SECRET || 'batmansecret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, 
        httpOnly: true,
        maxAge: 3600000,
        sameSite: 'lax' 
    }
}));

app.get('/login', (req, res) => {
    if (req.session && req.session.usuarioId) {
        return res.redirect('/');
    }
    res.render('login', { errores: null });
});

app.post('/login', async (req, res) => {
    const errores = validarUsuario(req.body, false);
    
    if (errores.length > 0) {
        return res.render('login', { 
            errores: errores,
            datos: req.body
        });
    }
    
    const { email, password } = req.body;

    console.log('Inicio de sesión intentado para:', req.body.email);
    
    try {
        const snapshot = await usuariosCollection.where('email', '==', email.trim().toLowerCase()).get();
        
        if (snapshot.empty) {
            return res.render('login', { 
                errores: ['Email o contraseña incorrectos'],
                datos: req.body
            });
        }
        
        let usuario = null;
        snapshot.forEach(doc => {
            usuario = {
                id: doc.id,
                ...doc.data()
            };
        });

        console.log('Usuario encontrado:', usuario ? usuario.id : 'no encontrado');
        
        if (!usuario || !verifyPassword(password, usuario.hash, usuario.salt)) {
            return res.render('login', { 
                errores: ['Email o contraseña incorrectos'],
                datos: req.body
            });
        }
        
        req.session.usuarioId = usuario.id;
        req.session.nombre = usuario.nombre;
        
        res.redirect('/');
        console.log('Sesión iniciada, ID:', req.session.usuarioId);
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        return res.render('login', { 
            errores: ['Error al iniciar sesión. Inténtalo más tarde.'],
            datos: req.body
        });
        console.error('Error detallado:', error);
    }
});

app.get('/registro', (req, res) => {
    if (req.session && req.session.usuarioId) {
        return res.redirect('/');
    }
    res.render('registro', { errores: null });
});

app.post('/registro', async (req, res) => {
    const errores = validarUsuario(req.body);
    
    if (errores.length > 0) {
        return res.render('registro', { 
            errores: errores,
            datos: req.body
        });
    }
    
    const { nombre, email, password } = req.body;
    
    try {
        const snapshot = await usuariosCollection.where('email', '==', email.trim().toLowerCase()).get();
        
        if (!snapshot.empty) {
            return res.render('registro', { 
                errores: ['El email ya está registrado'],
                datos: req.body
            });
        }
        
        const { hash, salt } = hashPassword(password);
        
        await usuariosCollection.add({
            nombre: nombre.trim(),
            email: email.trim().toLowerCase(),
            hash,
            salt,
            fechaCreacion: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.redirect('/login?registrado=1');
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        return res.render('registro', { 
            errores: ['Error al registrar usuario. Inténtalo más tarde.'],
            datos: req.body
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', requireLogin, async (req, res) => {
    try {
        const snapshot = await personajesCollection.get();
        const personajes = [];
        
        snapshot.forEach(doc => {
            personajes.push({
                id: doc.id,
                ...doc.data()
            });
        });
        
        res.render('index', { personajes: personajes, errores: null, nombre: req.session.nombre });
    } catch (error) {
        console.error('Error al obtener personajes:', error);
        res.status(500).send('Error al obtener personajes');
    }
});

app.use(async (err, req, res, next) => {
    if (err.type === 'entity.too.large' || 
        (err.message && err.message.includes('Payload demasiado grande')) ||
        (err.message && err.message.includes('request entity too large'))) {
        
        try {
            const snapshot = await personajesCollection.get();
            const personajes = [];
            
            snapshot.forEach(doc => {
                personajes.push({
                    id: doc.id,
                    ...doc.data()
                });
            });
            
            return res.render('index', { 
                personajes: personajes, 
                errores: ['El tamaño de los datos excede el límite permitido (máximo 1MB)'],
                datos: req.body || {}
            });
        } catch (error) {
            console.error('Error al obtener personajes:', error);
            return res.status(500).send('Error al obtener personajes');
        }
    } else {
        next(err);
    }
});

app.use((req, res, next) => {
    if (req.body && Object.keys(req.body).length > 20) {
        return res.status(400).send('Demasiados campos en la solicitud');
    }
    
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function validarCampos(datos) {
    const { nombre, alias, rol, edad, ciudad, habilidades, debilidades, descripcion } = datos;
    const errores = [];
    
    const limites = {
        nombre: 50,
        alias: 30,
        rol: 6,
        ciudad: 50,
        habilidades: 200,
        debilidades: 200,
        descripcion: 500
    };
    
    const MAX_INPUT_LENGTH = 10000;
    
    for (const [campo, valor] of Object.entries(datos)) {
        if (typeof valor === 'string') {
            if (valor.length > MAX_INPUT_LENGTH) {
                errores.push(`El campo ${campo} excede el tamaño máximo permitido.)`);
                datos[campo] = valor.substring(0, MAX_INPUT_LENGTH);
            }
        }
    }

    if (errores.length > 0) {
        return errores;
    }
    
    if (!nombre || nombre.trim() === '') errores.push('El nombre es obligatorio');
    else if (nombre.length > limites.nombre) errores.push(`El nombre no debe exceder ${limites.nombre} caracteres`);
    
    if (!alias || alias.trim() === '') errores.push('El alias es obligatorio');
    else if (alias.length > limites.alias) errores.push(`El alias no debe exceder ${limites.alias} caracteres`);
    
    const rolesPermitidos = ['héroe', 'villano', 'aliado'];
    if (!rol || rol.trim() === '') errores.push('El rol es obligatorio');
    else if (!rolesPermitidos.includes(rol)) errores.push('El rol debe ser héroe, villano o aliado');
    else if (rol.length > limites.rol) errores.push(`El rol no debe exceder ${limites.rol} caracteres`);
    
    if (!edad || isNaN(edad) || edad <= 0) errores.push('La edad debe ser un número positivo');
    else if (edad > 150) errores.push('La edad debe ser un valor razonable (máximo 150)');
    
    if (!ciudad || ciudad.trim() === '') errores.push('La ciudad es obligatoria');
    else if (ciudad.length > limites.ciudad) errores.push(`La ciudad no debe exceder ${limites.ciudad} caracteres`);
    
    if (!habilidades || habilidades.trim() === '') errores.push('Las habilidades son obligatorias');
    else if (habilidades.length > limites.habilidades) errores.push(`Las habilidades no deben exceder ${limites.habilidades} caracteres`);

    if (!debilidades || debilidades.trim() === '') errores.push('Las debilidades son obligatorias');
    else if (debilidades.length > limites.debilidades) errores.push(`Las debilidades no deben exceder ${limites.debilidades} caracteres`);
    
    if (!descripcion || descripcion.trim() === '') errores.push('La descripción es obligatoria');
    else if (descripcion.length > limites.descripcion) errores.push(`La descripción no debe exceder ${limites.descripcion} caracteres`);
    
    const contieneTags = (texto) => {
        return /<\/?[a-z][\s\S]*>/i.test(texto) || /<[a-z]+\s*$/i.test(texto) || /^\s*>[^<]*$/i.test(texto);       
    };
    
    const contieneScript = (texto) => {
        return /<script[\s\S]*?>|javascript:|on\w+\s*=|eval\(|new Function\(|document\.cookie/i.test(texto);
    };
    
    const contieneCaracteresPeligrosos = (texto) => {
        return /[\u0000-\u001F\u007F-\u009F\u2000-\u200F\uFEFF]/.test(texto);
    };
    
    const camposTexto = { nombre, alias, ciudad, habilidades, debilidades, descripcion };
    
    for (const [campo, valor] of Object.entries(camposTexto)) {
        if (typeof valor === 'string') {
            if (contieneTags(valor)) {
                errores.push(`El campo ${campo} contiene etiquetas HTML no permitidas`);
            }
            if (contieneScript(valor)) {
                errores.push(`El campo ${campo} contiene código JavaScript no permitido`);
            }
            if (contieneCaracteresPeligrosos(valor)) {
                errores.push(`El campo ${campo} contiene caracteres de control no permitidos`);
            }
        }
    }
    return errores;
}

function sanitizarDatos(datos) {
    const datosSanitizados = {};
    
    for (const [campo, valor] of Object.entries(datos)) {
        if (typeof valor === 'string') {
            datosSanitizados[campo] = valor.trim().replace(/\s+/g, ' ');
        } else {
            datosSanitizados[campo] = valor;
        }
    }
    
    if (datos.edad) {
        datosSanitizados.edad = parseInt(datos.edad, 10) || 0;
    }
    
    return datosSanitizados;
}

app.post('/registrar', async (req, res) => {
    const errores = validarCampos(req.body);
    
    if (errores.length > 0) {
        try {
            const snapshot = await personajesCollection.get();
            const personajes = [];
            
            snapshot.forEach(doc => {
                personajes.push({
                    id: doc.id,
                    ...doc.data()
                });
            });
            
            return res.render('index', { 
                personajes: personajes, 
                errores: errores,
                datos: req.body
            });
        } catch (error) {
            console.error('Error al obtener personajes:', error);
            return res.status(500).send('Error al obtener personajes');
        }
    }
    
    const datosSanitizados = sanitizarDatos(req.body);
    
    try {
        await personajesCollection.add({
            nombre: datosSanitizados.nombre,
            alias: datosSanitizados.alias,
            rol: datosSanitizados.rol,
            edad: datosSanitizados.edad,
            ciudad: datosSanitizados.ciudad,
            habilidades: datosSanitizados.habilidades,
            debilidades: datosSanitizados.debilidades,
            descripcion: datosSanitizados.descripcion
        });
        
        res.redirect('/');
    } catch (error) {
        console.error('Error al registrar personaje:', error);
        res.status(500).send('Error al registrar personaje');
    }
});

app.get('/editar/:id', async (req, res) => {
    const id = req.params.id;
    
    if (!id) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    try {
        const doc = await personajesCollection.doc(id).get();
        
        if (!doc.exists) {
            return res.redirect('/');
        }
        
        const personaje = {
            id: doc.id,
            ...doc.data()
        };
        
        res.render('editar', { personaje: personaje, errores: null });
    } catch (error) {
        console.error('Error al obtener datos para editar:', error);
        res.status(500).send('Error al obtener datos para editar');
    }
});

app.post('/actualizar/:id', async (req, res) => {
    const id = req.params.id;
    
    if (!id) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    const errores = validarCampos(req.body);
    
    if (errores.length > 0) {
        return res.render('editar', { 
            personaje: {
                id,
                ...req.body
            },
            errores: errores
        });
    }
    
    const datosSanitizados = sanitizarDatos(req.body);
    
    try {
        await personajesCollection.doc(id).update({
            nombre: datosSanitizados.nombre,
            alias: datosSanitizados.alias,
            rol: datosSanitizados.rol,
            edad: datosSanitizados.edad,
            ciudad: datosSanitizados.ciudad,
            habilidades: datosSanitizados.habilidades,
            debilidades: datosSanitizados.debilidades,
            descripcion: datosSanitizados.descripcion
        });
        
        res.redirect('/');
    } catch (error) {
        console.error('Error al actualizar personaje:', error);
        res.status(500).send('Error al actualizar personaje');
    }
});

app.post('/eliminar/:id', async (req, res) => {
    const id = req.params.id;
    
    if (!id) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    try {
        await personajesCollection.doc(id).delete();
        res.redirect('/');
    } catch (error) {
        console.error('Error al eliminar personaje:', error);
        res.status(500).send('Error al eliminar personaje');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));