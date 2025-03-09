require('dotenv').config();

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

const app = express();

// Configuración de Firebase con variables de entorno
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

// Inicializar Firebase
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Obtener referencia a Firestore
const db = admin.firestore();
const personajesCollection = db.collection('personajes');

// Middleware para procesar datos de formularios
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Configurar EJS como motor de plantillas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Función para validar campos
function validarCampos(datos) {
    const { nombre, alias, rol, edad, ciudad, habilidades, descripcion } = datos;
    const errores = [];
    
    // Validar que ningún campo esté vacío
    if (!nombre || nombre.trim() === '') errores.push('El nombre es obligatorio');
    if (!alias || alias.trim() === '') errores.push('El alias es obligatorio');
    if (!rol || rol.trim() === '') errores.push('El rol es obligatorio');
    if (!edad || isNaN(edad) || edad <= 0) errores.push('La edad debe ser un número positivo');
    if (!ciudad || ciudad.trim() === '') errores.push('La ciudad es obligatoria');
    if (!habilidades || habilidades.trim() === '') errores.push('Las habilidades son obligatorias');
    if (!descripcion || descripcion.trim() === '') errores.push('La descripción es obligatoria');
    
    // Validar que no contenga etiquetas HTML o JavaScript
    const contieneTags = (texto) => {
        // Regex que detecta etiquetas HTML/XML abiertas, cerradas, o parciales
        return /<\/?[a-z][\s\S]*>/i.test(texto) || 
               /<[a-z]+\s*$/i.test(texto) ||     // Tag que solo inicia
               /^\s*>[^<]*$/i.test(texto);       // Tag que solo termina
    };
    
    const contieneScript = (texto) => {
        // Regex que detecta tags <script> o código JavaScript sospechoso
        return /<script[\s\S]*?>|javascript:/i.test(texto);
    };
    
    // Verificar cada campo para tags HTML o código script
    const camposTexto = { nombre, alias, ciudad, habilidades, descripcion };
    
    for (const [campo, valor] of Object.entries(camposTexto)) {
        if (typeof valor === 'string') {
            if (contieneTags(valor)) {
                errores.push(`El campo ${campo} contiene etiquetas HTML no permitidas`);
            }
            if (contieneScript(valor)) {
                errores.push(`El campo ${campo} contiene código JavaScript no permitido`);
            }
        }
    }
    
    return errores;
}

// Página principal - mostrar formulario y lista
app.get('/', async (req, res) => {
    try {
        const snapshot = await personajesCollection.get();
        const personajes = [];
        
        snapshot.forEach(doc => {
            personajes.push({
                id: doc.id,
                ...doc.data()
            });
        });
        
        res.render('index', { personajes: personajes, errores: null });
    } catch (error) {
        console.error('Error al obtener personajes:', error);
        res.status(500).send('Error al obtener personajes');
    }
});

// Registrar un personaje
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
    
    const { nombre, alias, rol, edad, ciudad, habilidades, descripcion } = req.body;
    
    try {
        await personajesCollection.add({
            nombre,
            alias,
            rol,
            edad: parseInt(edad),
            ciudad,
            habilidades,
            descripcion
        });
        
        res.redirect('/');
    } catch (error) {
        console.error('Error al registrar personaje:', error);
        res.status(500).send('Error al registrar personaje');
    }
});

// Eliminar un personaje
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

// Editar un personaje (mostrar formulario con datos)
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

// Actualizar personaje
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
    
    const { nombre, alias, rol, edad, ciudad, habilidades, descripcion } = req.body;
    
    try {
        await personajesCollection.doc(id).update({
            nombre,
            alias,
            rol,
            edad: parseInt(edad),
            ciudad,
            habilidades,
            descripcion
        });
        
        res.redirect('/');
    } catch (error) {
        console.error('Error al actualizar personaje:', error);
        res.status(500).send('Error al actualizar personaje');
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));