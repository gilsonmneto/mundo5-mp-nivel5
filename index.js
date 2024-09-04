const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");

const app = express();

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
app.listen(port, () => {
	console.log(`Server is running on port ${port}`);
});

const secretKey = process.env.JWT_SECRET || "secretKey";
const users = [
	{ username: "user", password: "123456", id: 123, email: "user@dominio.com", perfil: "user" },
	{ username: "admin", password: "123456789", id: 124, email: "admin@dominio.com", perfil: "admin" },
	{ username: "colab", password: "123", id: 125, email: "colab@dominio.com", perfil: "user" },
];

// Função para gerar JWT
function generateToken(user) {
	return jwt.sign({ usuario_id: user.id, perfil: user.perfil }, secretKey, { expiresIn: "1h" });
}

// Middleware para validar JWT
function authenticateToken(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];

	if (token == null) return res.sendStatus(401);

	jwt.verify(token, secretKey, (err, user) => {
		if (err) return res.sendStatus(403);
		req.user = user;
		next();
	});
}

app.get("/", (req, res) => {
	return res.status(200).json({ message: "M5-MP-N5 'Software Sem Segurança Não Serve' está funcionando" });
});

// Endpoint para login do usuário
app.post("/api/auth/login", [check("username").notEmpty(), check("password").notEmpty()], (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({ errors: errors.array() });
	}

	const credentials = req.body;
	const userData = users.find(
		(user) => user.username === credentials.username && user.password === credentials.password
	);

	if (userData) {
		const token = generateToken(userData);
		res.json({ token });
	} else {
		res.status(401).json({ message: "Credenciais inválidas" });
	}
});

// Endpoint para recuperar os dados do usuário logado
app.get("/api/auth/me", authenticateToken, (req, res) => {
	res.json({ usuario_id: req.user.usuario_id, perfil: req.user.perfil });
});

// Endpoint para recuperação dos dados de todos os usuários cadastrados
app.get("/api/users", authenticateToken, (req, res) => {
	if (req.user.perfil !== "admin") {
		return res.status(403).json({ message: "Forbidden" });
	}
	res.status(200).json({ data: users });
});

// Endpoint para recuperação dos contratos existentes
app.get(
	"/api/contracts/:empresa/:inicio",
	authenticateToken,
	[check("empresa").notEmpty(), check("inicio").isISO8601()],
	(req, res) => {
		if (req.user.perfil !== "admin") {
			return res.status(403).json({ message: "Forbidden" });
		}

		const { empresa, inicio } = req.params;

		const result = getContracts(empresa, inicio);
		if (result) res.status(200).json({ data: result });
		else res.status(404).json({ data: "Dados Não encontrados" });
	}
);

// Função para realizar a busca de contratos (exemplo)
function getContracts(empresa, inicio) {
	// Validação e sanitização de parâmetros
	if (typeof empresa !== "string" || !empresa.trim()) {
		return null;
	}

	const repository = new Repository();
	const query = `SELECT * FROM contracts WHERE empresa = ? AND data_inicio = ?`;
	const result = repository.execute(query, [empresa, inicio]);

	return result;
}

// Classe fake emulando um script externo, responsável pela execução de queries no banco de dados
class Repository {
	execute(query, params) {
		// Query parametrizada para evitar SQL Injection
		// Implementação real deveria usar uma biblioteca de acesso ao banco de dados segura, como Sequelize
		console.log(`Executing query: ${query} with params: ${params}`);
		return [];
	}
}
