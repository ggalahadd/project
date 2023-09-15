const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const app = express();
const port = 3001;

// Сессия
app.use(session({
  secret: 'your-secret-key',
  resave: false, // Запрет пересохранения сессии
  saveUninitialized: true // Сохранение сессии только при аутентификации
}));

app.use(bodyParser.urlencoded({ extended: true })); // Парсинг данных из формы
app.use(express.static(__dirname + '/public')); // Подключение статических файлов (CSS, JavaScript, изображения)

// Коннект к БД
const connection = mysql.createConnection({
  host: '172.17.0.3',
  user: 'guest',
  password: 'guestpass123',
  database: 'Project',
  port: 3366
});

connection.connect(err => {
  if (err) {
    console.error('Ошибка подключения к базе данных: ' + err.message);
  } else {
    console.log('Подключение к базе данных успешно установлено');
  }
});

app.get('/checkauth', (req, res) => {
  const isAuthenticated = !!req.session.loggedInUser; // Проверяем наличие пользователя в сессии
  res.json({ authenticated: isAuthenticated }); // Отправляем ответ с результатом проверки
});

// Маршрут для страницы логина
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/html/login.html'); // Отправляем страницу для входа
});

// Маршрут для страницы регистрации
app.get('/registration', (req, res) => {
  res.sendFile(__dirname + '/html/registration.html'); // Отправляем страницу для регистрации
});

// Маршрут для главной страницы
app.get('/main', (req, res) => {
  res.sendFile(__dirname + '/html/main.html'); // Отправляем главную страницу
});

// Обработка запроса на вход
app.post('/login', (req, res) => {
  const { login, password } = req.body; // Получаем логин и пароль из запроса
  connection.query(
    'SELECT * FROM user_info WHERE login = ?', // SQL-запрос для получения информации о пользователе по логину
    [login],
    (err, results) => {
      if (err) {
        console.error('Ошибка выполнения SQL-запроса: ' + err.message);
        res.status(500).send('Ошибка сервера');
      } else {
        if (results.length > 0) {
          const storedHashedPassword = results[0].password; // Получаем хешированный пароль из БД

          // Сравниваем введенный пароль с хешированным паролем
          bcrypt.compare(password, storedHashedPassword, (compareErr, isMatch) => {
            if (compareErr) {
              console.error('Ошибка при сравнении паролей: ' + compareErr.message);
              res.status(500).send('Ошибка сервера');
            } else {
              if (isMatch) {
                // Пользователь аутентифицирован, устанавливаем сессию
                req.session.loggedInUser = login;
                res.redirect('/main'); // Перенаправляем на страницу "main"
              } // Перенаправляем на страницу "main"
              else {
                res.send('Неверный логин или пароль');
              }
            }
          });
        } else {
          res.send('Неверный логин или пароль');
        }
      }
    }
  );
});

// Обработка запроса на регистрацию
app.post('/register', (req, res) => {
  const { login, password } = req.body; // Получаем логин и пароль из запроса
  const saltRounds = 10;

  // Хешируем пароль с использованием bcryptjs
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Ошибка хеширования пароля: ' + err.message);
      res.status(500).send('Ошибка сервера');
    } else {
      // Проверяем, есть ли пользователь с таким логином в базе данных
      connection.query(
        'SELECT * FROM user_info WHERE login = ?',
        [login],
        (err, results) => {
          if (err) {
            console.error('Ошибка выполнения SQL-запроса: ' + err.message);
            res.status(500).send('Ошибка сервера');
          } else {
            if (results.length > 0) {
              res.send('Пользователь с таким логином уже существует');
            } else {
              // Если пользователя с таким логином нет, то добавляем его
              connection.query(
                'INSERT INTO user_info (login, password) VALUES (?, ?)',
                [login, hash], // Сохраняем хеш пароля, а не сам пароль
                (err, result) => {
                  if (err) {
                    console.error('Ошибка выполнения SQL-запроса: ' + err.message);
                    res.status(500).send('Ошибка сервера');
                  } else {
                    res.redirect('/');
                  }
                }
              );
            }
          }
        }
      );
    }
  });
});


// Обработка запроса на добавление заметки
app.post('/addnote', (req, res) => {
  const { note } = req.body;
  const user = req.session.loggedInUser; // Получаем логин пользователя из сессии

  connection.query(
    'INSERT INTO notes (user, text) VALUES (?, ?)',
    [user, note],
    (err, result) => {
      if (err) {
        console.error('Ошибка выполнения SQL-запроса: ' + err.message);
        res.status(500).send('Ошибка сервера');
      } else {
        res.redirect('/main'); // Перенаправляем на главную страницу
      }
    }
  );
});

// Маршрут для получения списка заметок
app.get('/getnotes', (req, res) => {
  connection.query('SELECT * FROM notes', (err, results) => {
    if (err) {
      console.error('Ошибка выполнения SQL-запроса: ' + err.message);
      res.status(500).send('Ошибка сервера');
    } else {
      const notes = results.map(result => result.text);
      res.json({ notes }); // Отправляем список заметок в формате JSON
    }
  });
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
