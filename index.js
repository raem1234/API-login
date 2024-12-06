require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // Importación única de nodemailer
const Usuario = require('./models/usuario');
const crypto = require('crypto');
const cors = require('cors'); // Importa el paquete CORS

const app = express();
app.use(express.json());

// Configuración de CORS para permitir solicitudes del frontend
app.use(cors({
  origin: 'http://localhost:3000', // Ajusta esto si es necesario para otros orígenes
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error('Error al conectar a MongoDB:', err));

// Configuración del transporte de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,  // Tu correo electrónico
    pass: process.env.EMAIL_PASS   // Contraseña o contraseña de aplicación
  }
});

// Rutas
// Registro de usuario
app.post('/registro', async (req, res) => {
  const { nombre, correo, contraseña } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(contraseña, salt);
    const nuevoUsuario = new Usuario({ nombre, correo, contraseña: hash });
    await nuevoUsuario.save();
    res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
  } catch (err) {
    res.status(400).json({ error: 'Error al registrar el usuario', detalle: err });
  }
});

// Inicio de sesión
app.post('/login', async (req, res) => {
  const { correo, contraseña } = req.body;

  try {
    const usuario = await Usuario.findOne({ correo });
    if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

    const esValido = await bcrypt.compare(contraseña, usuario.contraseña);
    if (!esValido) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ mensaje: 'Inicio de sesión exitoso', token });
  } catch (err) {
    res.status(500).json({ error: 'Error al iniciar sesión', detalle: err });
  }
});

// Recuperación de contraseña
app.put('/recuperar', async (req, res) => {
  const { correo } = req.body;

  try {
    const usuario = await Usuario.findOne({ correo });
    if (!usuario) return res.status(404).json({ error: 'Correo no registrado' });

    const nuevaContraseña = crypto.randomBytes(8).toString('hex');
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(nuevaContraseña, salt);

    usuario.contraseña = hash;
    await usuario.save();

    // Enviar correo con la nueva contraseña
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: correo,
      subject: 'Recuperación de contraseña',
      text: `Tu nueva contraseña es: ${nuevaContraseña}`,
    });

    res.json({ mensaje: 'Correo de recuperación enviado' });
  } catch (err) {
    console.error('Error al recuperar la contraseña:', err);
    res.status(500).json({ error: 'Error al recuperar la contraseña', detalle: err.message });
  }
});

// Listar todos los usuarios (excluyendo la contraseña)
app.get('/usuarios', async (req, res) => {
  try {
    const usuarios = await Usuario.find({}, { contraseña: 0 }); // Excluir contraseña
    res.json(usuarios);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuarios', detalle: err });
  }
});

// Inicio del servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
