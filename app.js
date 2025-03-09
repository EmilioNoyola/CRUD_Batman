require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();

// Configuración de la base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('Conectado a MySQL');
});

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
app.get('/', (req, res) => {
    db.query('SELECT * FROM personajes', (err, resultados) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al obtener personajes');
        }
        res.render('index', { personajes: resultados, errores: null });
    });
});

// Registrar un personaje
app.post('/registrar', (req, res) => {
    const errores = validarCampos(req.body);
    
    if (errores.length > 0) {
        // Si hay errores, cargar de nuevo la página con los errores
        db.query('SELECT * FROM personajes', (err, resultados) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error al obtener personajes');
            }
            return res.render('index', { 
                personajes: resultados, 
                errores: errores,
                datos: req.body // Devuelve los datos para que el usuario no tenga que escribirlos de nuevo
            });
        });
        return;
    }
    
    const { nombre, alias, rol, edad, ciudad, habilidades, descripcion } = req.body;
    const sql = 'INSERT INTO personajes (nombre, alias, rol, edad, ciudad, habilidades, descripcion) VALUES (?, ?, ?, ?, ?, ?, ?)';
    
    db.query(sql, [nombre, alias, rol, edad, ciudad, habilidades, descripcion], err => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al registrar personaje');
        }
        res.redirect('/');
    });
});

// Eliminar un personaje
app.post('/eliminar/:id', (req, res) => {
    const id = req.params.id;
    
    if (!id || isNaN(parseInt(id))) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    db.query('DELETE FROM personajes WHERE id = ?', [id], err => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al eliminar personaje');
        }
        res.redirect('/');
    });
});

// Editar un personaje (mostrar formulario con datos)
app.get('/editar/:id', (req, res) => {
    const id = req.params.id;
    
    if (!id || isNaN(parseInt(id))) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    db.query('SELECT * FROM personajes WHERE id = ?', [id], (err, resultado) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al obtener datos para editar');
        }
        if (resultado.length === 0) return res.redirect('/');

        res.render('editar', { personaje: resultado[0], errores: null });
    });
});

// Actualizar personaje
app.post('/actualizar/:id', (req, res) => {
    const id = req.params.id;
    
    if (!id || isNaN(parseInt(id))) {
        return res.status(400).send('ID de personaje inválido');
    }
    
    const errores = validarCampos(req.body);
    
    if (errores.length > 0) {
        // Si hay errores, volver a mostrar el formulario con los errores
        return res.render('editar', { 
            personaje: req.body,
            errores: errores
        });
    }
    
    const { nombre, alias, rol, edad, ciudad, habilidades, descripcion } = req.body;
    db.query('UPDATE personajes SET nombre=?, alias=?, rol=?, edad=?, ciudad=?, habilidades=?, descripcion=? WHERE id=?',
        [nombre, alias, rol, edad, ciudad, habilidades, descripcion, id], err => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error al actualizar personaje');
            }
            res.redirect('/');
        });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));